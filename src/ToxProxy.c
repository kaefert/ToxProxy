/*
 ============================================================================
 Name        : ToxProxy.c
 Author      : Thomas Käfer
 Version     : 0.1
 Copyright   : 2019

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

 ============================================================================
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>

#include <pthread.h>

#include <semaphore.h>
#include <signal.h>
#include <linux/sched.h>

// gives bin2hex & hex2bin functions for Tox-ID / public-key conversions
#include <sodium/utils.h>

// tox core
#include <tox/tox.h>
#ifdef TOX_HAVE_TOXUTIL
    #include <tox/toxutil.h>
#endif

// timestamps for printf output
#include <time.h>
#include <sys/time.h>

// mkdir -> https://linux.die.net/man/2/mkdir
#include <sys/stat.h>
#include <sys/types.h>






typedef struct DHT_node {
    const char *ip;
    uint16_t port;
    const char key_hex[TOX_PUBLIC_KEY_SIZE*2 + 1];
    unsigned char key_bin[TOX_PUBLIC_KEY_SIZE];
} DHT_node;

#define CURRENT_LOG_LEVEL 9 // 0 -> error, 1 -> warn, 2 -> info, 9 -> debug
#define c_sleep(x) usleep_usec(1000*x)


FILE *logfile = NULL;
const char *log_filename = "toxproxy.log";
const char *savedata_filename = "savedata.tox";
const char *savedata_tmp_filename = "savedata.tox.tmp";

uint32_t tox_public_key_hex_size;
uint32_t tox_address_hex_size;
int tox_loop_running = 1;






void dbg(int level, const char *fmt, ...)
{
    char *level_and_format = NULL;
    char *fmt_copy = NULL;

    if (fmt == NULL)
    {
        return;
    }

    if (strlen(fmt) < 1)
    {
        return;
    }

    if (!logfile)
    {
        return;
    }

    if ((level < 0) || (level > 9))
    {
        level = 0;
    }

    level_and_format = calloc(1, strlen(fmt) + 3 + 1);

    if (!level_and_format)
    {
        return;
    }

    fmt_copy = level_and_format + 2;
    strcpy(fmt_copy, fmt);
    level_and_format[1] = ':';

    if (level == 0)
    {
        level_and_format[0] = 'E';
    }
    else if (level == 1)
    {
        level_and_format[0] = 'W';
    }
    else if (level == 2)
    {
        level_and_format[0] = 'I';
    }
    else
    {
        level_and_format[0] = 'D';
    }

    level_and_format[(strlen(fmt) + 2)] = '\0'; // '\0' or '\n'
    level_and_format[(strlen(fmt) + 3)] = '\0';
    time_t t3 = time(NULL);
    struct tm tm3 = *localtime(&t3);
    char *level_and_format_2 = calloc(1, strlen(level_and_format) + 5 + 3 + 3 + 1 + 3 + 3 + 3 + 1);
    level_and_format_2[0] = '\0';
    snprintf(level_and_format_2, (strlen(level_and_format) + 5 + 3 + 3 + 1 + 3 + 3 + 3 + 1),
             "%04d-%02d-%02d %02d:%02d:%02d:%s",
             tm3.tm_year + 1900, tm3.tm_mon + 1, tm3.tm_mday,
             tm3.tm_hour, tm3.tm_min, tm3.tm_sec, level_and_format);

    if (level <= CURRENT_LOG_LEVEL)
    {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(logfile, level_and_format_2, ap);
        va_end(ap);
    }

    if (level_and_format)
    {
        free(level_and_format);
    }

    if (level_and_format_2)
    {
        free(level_and_format_2);
    }
}

time_t get_unix_time(void)
{
    return time(NULL);
}

void usleep_usec(uint64_t usec)
{
    struct timespec ts;
    ts.tv_sec = usec / 1000000;
    ts.tv_nsec = (usec % 1000000) * 1000;
    nanosleep(&ts, NULL);
}

Tox *create_tox()
{
    Tox *tox;

    struct Tox_Options options;

    tox_options_default(&options);

    FILE *f = fopen(savedata_filename, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);

        char *savedata = malloc(fsize);

        fread(savedata, fsize, 1, f);
        fclose(f);

        options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
        options.savedata_data = savedata;
        options.savedata_length = fsize;

#ifdef TOX_HAVE_TOXUTIL
        tox = tox_utils_new(&options, NULL);
#else
        tox = tox_new(&options, NULL);
#endif

        free(savedata);
    } else {
#ifdef TOX_HAVE_TOXUTIL
        tox = tox_utils_new(&options, NULL);
#else
        tox = tox_new(&options, NULL);
#endif
    }

    return tox;
}


void sigint_handler(int signo)
{
    if (signo == SIGINT)
    {
        printf("received SIGINT, pid=%d\n", getpid());
        tox_loop_running = 0;
    }
}


void update_savedata_file(const Tox *tox)
{
    size_t size = tox_get_savedata_size(tox);
    char *savedata = malloc(size);
    tox_get_savedata(tox, savedata);

    FILE *f = fopen(savedata_tmp_filename, "wb");
    fwrite(savedata, size, 1, f);
    fclose(f);

    rename(savedata_tmp_filename, savedata_filename);

    free(savedata);
}

void bootstrap(Tox *tox)
{
    DHT_node nodes[] =
    {
        {"178.62.250.138",             33445, "788236D34978D1D5BD822F0A5BEBD2C53C64CC31CD3149350EE27D4D9A2F9B6B", {0}},
        {"2a03:b0c0:2:d0::16:1",       33445, "788236D34978D1D5BD822F0A5BEBD2C53C64CC31CD3149350EE27D4D9A2F9B6B", {0}},
        {"tox.zodiaclabs.org",         33445, "A09162D68618E742FFBCA1C2C70385E6679604B2D80EA6E84AD0996A1AC8A074", {0}},
        {"163.172.136.118",            33445, "2C289F9F37C20D09DA83565588BF496FAB3764853FA38141817A72E3F18ACA0B", {0}},
        {"2001:bc8:4400:2100::1c:50f", 33445, "2C289F9F37C20D09DA83565588BF496FAB3764853FA38141817A72E3F18ACA0B", {0}},
        {"128.199.199.197",            33445, "B05C8869DBB4EDDD308F43C1A974A20A725A36EACCA123862FDE9945BF9D3E09", {0}},
        {"2400:6180:0:d0::17a:a001",   33445, "B05C8869DBB4EDDD308F43C1A974A20A725A36EACCA123862FDE9945BF9D3E09", {0}},
        {"node.tox.biribiri.org",      33445, "F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67", {0}}
    };

    for (size_t i = 0; i < sizeof(nodes)/sizeof(DHT_node); i ++) {
        sodium_hex2bin(nodes[i].key_bin, sizeof(nodes[i].key_bin),
                       nodes[i].key_hex, sizeof(nodes[i].key_hex)-1, NULL, NULL, NULL);
        tox_bootstrap(tox, nodes[i].ip, nodes[i].port, nodes[i].key_bin, NULL);
    }
}

void print_startup_message(Tox *tox)
{
    uint8_t tox_id_bin[tox_address_size()];
    tox_self_get_address(tox, tox_id_bin);
    char tox_id_hex[tox_address_hex_size];
    bin2upHex(tox_id_bin, tox_address_size(), tox_id_hex, tox_address_hex_size);

    size_t friends = tox_self_get_friend_list_size(tox);
    struct timeval tv;
	gettimeofday(&tv, NULL);
	struct tm tm = *localtime(&tv.tv_sec);
    printf("%d-%02d-%02d %02d:%02d:%02d.%ld ToxProxy startup completed. My Tox ID = %s ; Number of friends = %zu\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec, tox_id_hex, friends);

}

void writeMessage(char *sender_key_hex, const uint8_t *message, size_t length)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	struct tm tm = *localtime(&tv.tv_sec);
    printf("%d-%02d-%02d %02d:%02d:%02d.%ld New message from %s: %s\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec, sender_key_hex, message);

    const char *msgsDir = "./messages";
    char userDir[tox_public_key_hex_size+strlen(msgsDir)+1];
    strcpy(userDir, msgsDir);
    strcat(userDir, "/");
    strcat(userDir, sender_key_hex);

    mkdir(msgsDir, 0700);
    mkdir(userDir, 0700);

    char timestamp[4+1+2+1+2+1+4+1+2+1+6] = "0000-00-00_0000-00,000000";
    snprintf(timestamp, sizeof(timestamp), "%d-%02d-%02d_%02d%02d-%02d,%ld", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);

    char msgPath[sizeof(userDir)+1+sizeof(timestamp)+4];
    strcpy(msgPath, userDir);
    strcat(msgPath, "/");
    strcat(msgPath, timestamp);
    strcat(msgPath, ".txt");

    FILE *f = fopen(msgPath, "wb");
    fwrite(message, length, 1, f);
    fclose(f);
}

void friend_request_cb(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length,
                                   void *user_data)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	struct tm tm = *localtime(&tv.tv_sec);

    char public_key_hex[tox_public_key_hex_size];
	bin2upHex(public_key, tox_public_key_size, &public_key_hex, tox_public_key_hex_size);

    size_t friends = tox_self_get_friend_list_size(tox);
    printf("%d-%02d-%02d %02d:%02d:%02d.%ld Got currently %zu friends. New friend request from %s with message: %s\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec, friends, public_key_hex, message);

    writeMessage(&public_key_hex, message, length);

    tox_friend_add_norequest(tox, public_key, NULL);
    update_savedata_file(tox);

    friends = tox_self_get_friend_list_size(tox);
	gettimeofday(&tv, NULL);
	tm = *localtime(&tv.tv_sec);
    printf("%d-%02d-%02d %02d:%02d:%02d.%ld Added friend: %s. Number of total friends: %zu\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec, public_key_hex, friends);
}

void bin2upHex(uint8_t *bin, uint32_t bin_size, char *hex, uint32_t hex_size)
{
	sodium_bin2hex(hex, hex_size, bin, bin_size);
	for (size_t i = 0; i < hex_size-1; i ++) {
		hex[i] = toupper(hex[i]);
	}
}

void friend_message_cb(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message,
                                   size_t length, void *user_data)
{
    tox_friend_send_message(tox, friend_number, type,
                            "YOU are using the old Message format! this is not supported!",
                            length, NULL);

    uint8_t public_key_bin[tox_public_key_size()];
    tox_friend_get_public_key(tox, friend_number, public_key_bin, NULL);
    char public_key_hex[tox_public_key_hex_size];
    bin2upHex(&public_key_bin, tox_public_key_size(), &public_key_hex, tox_public_key_hex_size);
    writeMessage(&public_key_hex, message, length);
}

void friendlist_onConnectionChange(Tox *m, uint32_t num, TOX_CONNECTION connection_status, void *user_data)
{
    dbg(2, "friendlist_onConnectionChange:*READY*:friendnum=%d %d\n", (int)num, (int)connection_status);
}

void self_connection_status_cb(Tox *tox, TOX_CONNECTION connection_status, void *user_data)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	struct tm tm = *localtime(&tv.tv_sec);

    switch (connection_status) {
        case TOX_CONNECTION_NONE:
        	printf("%d-%02d-%02d %02d:%02d:%02d.%ld Connection Status changed to: Offline\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);
            break;
        case TOX_CONNECTION_TCP:
        	printf("%d-%02d-%02d %02d:%02d:%02d.%ld Connection Status changed to: Online via TCP\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);
            break;
        case TOX_CONNECTION_UDP:
        	printf("%d-%02d-%02d %02d:%02d:%02d.%ld Connection Status changed to: Online via UDP\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);
            break;
    }
}

//
// cut message at 999 chars length !!
//
void send_text_message_to_friend(Tox *tox, uint32_t friend_number, const char *fmt, ...)
{
    char msg2[1000];
    size_t length = 0;

    if (fmt == NULL)
    {
        dbg(9, "send_text_message_to_friend:no message to send\n");
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg2, 999, fmt, ap);
    va_end(ap);
    length = (size_t)strlen(msg2);
#ifdef TOX_HAVE_TOXUTIL
    uint32_t ts_sec = (uint32_t)get_unix_time();
    tox_util_friend_send_message_v2(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                    ts_sec, (const uint8_t *)msg2, length,
                                    NULL, NULL, NULL,
                                    NULL);
#else
    // old message format, not support by this proxy!
    tox_friend_send_message(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL, (uint8_t *)msg2, length, NULL);
#endif
}


void friend_message_v2_cb(Tox *tox, uint32_t friend_number,
                       const uint8_t *raw_message, size_t raw_message_len)
{
#ifdef TOX_HAVE_TOXUTIL
    // now get the real data from msgV2 buffer
    uint8_t *message_text = calloc(1, raw_message_len);

    if (message_text)
    {
        uint32_t ts_sec = tox_messagev2_get_ts_sec(raw_message);
        uint16_t ts_ms = tox_messagev2_get_ts_ms(raw_message);
        uint32_t text_length = 0;
        bool res = tox_messagev2_get_message_text(raw_message,
                   (uint32_t)raw_message_len,
                   (bool)false, (uint32_t)0,
                   message_text, &text_length);
        dbg(9, "friend_message_v2_cb:fn=%d res=%d msg=%s\n", (int)friend_number, (int)res,
            (char *)message_text);

        // for now echo the message back to the friend
        send_text_message_to_friend(tox, friend_number, (char *)message_text);
        free(message_text);
    }

#endif
}


int main(int argc, char *argv[])
{
    logfile = fopen(log_filename, "wb");
    setvbuf(logfile, NULL, _IONBF, 0);

    Tox *tox = create_tox();

    tox_public_key_hex_size = tox_public_key_size()*2 + 1;
    tox_address_hex_size = tox_address_size()*2 + 1;

    const char *name = "Echo Bot";
    tox_self_set_name(tox, name, strlen(name), NULL);

    const char *status_message = "Echoing your messages";
    tox_self_set_status_message(tox, status_message, strlen(status_message), NULL);

    bootstrap(tox);

    print_startup_message(tox);

    tox_callback_friend_request(tox, friend_request_cb);
    tox_callback_friend_message(tox, friend_message_cb);

#ifdef TOX_HAVE_TOXUTIL
    tox_utils_callback_self_connection_status(tox, self_connection_status_cb);
    tox_callback_self_connection_status(tox, tox_utils_self_connection_status_cb);
    tox_utils_callback_friend_connection_status(tox, friendlist_onConnectionChange);
    tox_callback_friend_connection_status(tox, tox_utils_friend_connection_status_cb);
    tox_utils_callback_friend_message_v2(tox, friend_message_v2_cb);
#else
    tox_callback_self_connection_status(tox, self_connection_status_cb);
    tox_callback_friend_connection_status(tox, friendlist_onConnectionChange);
#endif

    update_savedata_file(tox);


    long long unsigned int cur_time = time(NULL);
    long long loop_counter = 0;
    int max_tries = 2;
    int try = 0;
    uint8_t off = 1;

    while (1)
    {
        tox_iterate(tox, NULL);
        usleep_usec(tox_iteration_interval(tox) * 1000);

        if (tox_self_get_connection_status(tox) && off)
        {
            dbg(2, "Tox online, took %llu seconds\n", time(NULL) - cur_time);
            off = 0;
            break;
        }

        c_sleep(20);
        loop_counter++;

        if (loop_counter > (50 * 20))
        {
            try++;

            loop_counter = 0;
            // if not yet online, bootstrap every 20 seconds
            dbg(2, "Tox NOT online yet, bootstrapping again\n");
            bootstrap(tox);

            if (try >= max_tries)
            {
                // break the loop and start anyway
                // we will bootstrap again later if we are not online every few seconds
                break;
            }
        }
    }


    tox_loop_running = 1;
    signal(SIGINT, sigint_handler);
    pthread_setname_np(pthread_self(), "t_main");


    while (tox_loop_running) {
        tox_iterate(tox, NULL);
        usleep(tox_iteration_interval(tox) * 1000);
    }

#ifdef TOX_HAVE_TOXUTIL
    tox_utils_kill(tox);
#else
    tox_kill(tox);
#endif

    if (logfile)
    {
        fclose(logfile);
        logfile = NULL;
    }
    // HINT: for gprof you need an "exit()" call
    exit(0);
}
