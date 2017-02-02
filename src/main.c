/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include "bridge.h"

static void main_process(const char *ns_pid, const char *address, int fd)
{
    const char *container = "LanQPreactor";
   
    if (bridge_setup(address, container, ns_pid) < 0)
        exit(1);

    if (fd > 0) {
        write(fd, "0", 1); // Success signal
        close(fd);
    }

    bridge_run(500000);
   
}

static void daemon_process(const char *ns_pid, const char *pidfile, const char *address, const char *user)
{
    int pipefd[2];

    //
    // This daemonization process is based on that outlined in the
    // "daemon" manpage from Linux.
    //

    //
    // Create an unnamed pipe for communication from the daemon to the main process
    //
    if (pipe(pipefd) < 0) {
        perror("Error creating inter-process pipe");
        exit(1);
    }

    //
    // First fork
    //
    pid_t pid = fork();
    if (pid == 0) {
        //
        // Child Process
        //

        //
        // Detach any terminals and create an independent session
        //
        if (setsid() < 0) {
            write(pipefd[1], "1", 1);
            exit(0);
        }

        //
        // Second fork
        //
        pid_t pid2 = fork();
        if (pid2 == 0) {
            close(pipefd[0]); // Close read end.

            //
            // Assign stdin, stdout, and stderr to /dev/null
            //
            close(2);
            close(1);
            close(0);
            int fd = open("/dev/null", O_RDWR);
            if (fd != 0) {
                write(pipefd[1], "2", 1);
                exit(0);
            }
            if (dup(fd) < 0) {
                write(pipefd[1], "3", 1);
                exit(0);
            }
            if (dup(fd) < 0) {
                write(pipefd[1], "4", 1);
                exit(0);
            }

            //
            // Set the umask to 0
            //
            if (umask(0) < 0) {
                write(pipefd[1], "5", 1);
                exit(0);
            }

            //
            // Set the current directory to "/" to avoid blocking
            // mount points
            //
            if (chdir("/") < 0) {
                write(pipefd[1], "6", 1);
                exit(0);
            }

            //
            // If a pidfile was provided, write the daemon pid there.
            //
            if (pidfile) {
                FILE *pf = fopen(pidfile, "w");
                if (pf == 0) {
                    write(pipefd[1], "7", 1);
                    exit(0);
                }
                fprintf(pf, "%d\n", getpid());
                fclose(pf);
            }

            //
            // If a user was provided, drop privileges to the user's
            // privilege level.
            //
            if (user) {
                struct passwd *pwd = getpwnam(user);
                if (pwd == 0) {
                    write(pipefd[1], "8", 1);
                    exit(0);
                }
                if (setuid(pwd->pw_uid) < 0) {
                    write(pipefd[1], "9", 1);
                    exit(0);
                }
                if (setgid(pwd->pw_gid) < 0) {
                    write(pipefd[1], "A", 1);
                    exit(0);
                }
            }

            main_process(ns_pid, address, pipefd[1]);
        } else
            //
            // Exit first child
            //
            exit(0);
    } else {
        //
        // Parent Process
        // Wait for a success signal ('0') from the daemon process.
        // If we get success, exit with 0.  Otherwise, exit with 1.
        //
        char code;
        close(pipefd[1]); // Close write end.
        if (read(pipefd[0], &code, 1) < 0) {
            perror("Error reading inter-process pipe");
            exit(1);
        }

        if (code == '0')
            exit(0);
        fprintf(stderr, "Error occurred during daemon initialization, please see logs.  [code=%c]\n", code);
        exit(1);
    }
}

int main(int argc, char **argv)
{
    const char *address = "127.0.0.1";
    const char *ns_pid  = 0;
    const char *pidfile = 0;
    const char *user    = 0;
    bool        daemon_mode = false;
    
    static struct option long_options[] = {
    {"daemon",  no_argument,       0, 'd'},
    {"pidfile", required_argument, 0, 'P'},
    {"user",    required_argument, 0, 'U'},
    {"help",    no_argument,       0, 'h'},
    {0,         0,                 0,  0}
    };

   
    while (1) {
        int c = getopt_long(argc, argv, "a:dP:U:h", long_options, 0);
        if (c == -1)
            break;

        switch (c) {
        case 'a' :
            address = optarg;
            break;
            
        case 'd' :
            daemon_mode = true;
            break;

        case 'P' :
            pidfile = optarg;
            break;

        case 'U' :
            user = optarg;
            break;

        case 'h' :
            printf("Usage: %s [OPTIONS]\n\n", argv[0]);
            printf("  -a, --address              Message bus connection address\n");
            printf("  -d, --daemon               Run process as a SysV-style daemon\n");
            printf("  -P, --pidfile              If daemon, the file for the stored daemon pid\n");
            printf("  -U, --user                 If daemon, the username to run as\n");
            printf("  -h, --help                 Print this help\n");
            exit(0);

        case '?' :
            exit(1);
        }
    }
    
    if (daemon_mode)
        daemon_process(ns_pid, pidfile, address, user);
    else
        main_process(ns_pid, address, -1);

    return 0;
    
}
