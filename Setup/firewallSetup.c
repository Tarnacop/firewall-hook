#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#define KERNEL_PROC_NAME "/proc/firewallExtension"

int main(int argc, char** argv) {

    FILE* rules_file;
    size_t length;
    char* firewall_rule_ptr = NULL;
    char* validation_ptr;
    int process_fd;

    /* Check if the program is executed correctly */
    /* If we have 2 arguments, the second argument must be the list command */
    if(argc == 2) {

        if(strcmp(argv[1], "L") != 0) {

            fprintf(stderr, "Usage: %s L\n", argv[0]);
            fprintf(stderr, "Usage: %s W <rules file>\n", argv[0]);
            exit(1);
        }

        /* Open the process file for reading */
        process_fd = open(KERNEL_PROC_NAME, O_RDONLY);
        if(process_fd == -1) {
            fprintf(stderr, "ERROR: An error occurred while opening the file. %s\n", strerror(errno));
            exit(1);
        }

        /* Read triggers writing to log */
        read(process_fd, NULL, 0);

        /* Close the file */
        close(process_fd);

        exit(0);

        /* Else if we have 3 arguments, the second argument must be the write command */
    } else if(argc == 3) {

        if(strcmp(argv[1], "W") != 0) {

            fprintf(stderr, "Usage: %s L\n", argv[0]);
            fprintf(stderr, "Usage: %s W <rules file>\n", argv[0]);
            exit(1);
        }

        /* Open the input file containing the rules */
        rules_file = fopen(argv[2], "r");
        /* Open the process file for writing */
        process_fd = open(KERNEL_PROC_NAME, O_WRONLY);
        /* If we could not open one of the files */
        if(!rules_file || (process_fd == -1)) {
            fprintf(stderr, "ERROR: An error occurred while opening one of the files. %s\n", strerror(errno));
            exit(1);
        }

        while((getline(&firewall_rule_ptr, &length, rules_file)) != -1) {
            /* Try and allocate space to keep the first rule */
            validation_ptr = malloc((strlen(firewall_rule_ptr) + 1) * sizeof(char));

            if(!validation_ptr) {
                fprintf(stderr, "ERROR: Could not allocate memory");
                fclose(rules_file);
                close(process_fd);
                exit(1);
            }

            /* Copy the rule into the firewall rule */
            strcpy(validation_ptr, firewall_rule_ptr);
            int arguments_counter = 0;
            char* aux_ptr = NULL;
            char* original_ptr = validation_ptr;
            while((aux_ptr = strsep(&validation_ptr, " \n\r")) != NULL) {

                /* If we check the port now */
                if(arguments_counter == 0) {

                    char* endptr = NULL;
                    strtol(aux_ptr, &endptr, 10);
                    if(endptr != NULL) {
                        /* Let -2 mark Ill-formed file */
                        arguments_counter = -2;
                        break;
                    }
                /* If we check for the path */
                } else if(arguments_counter == 1) {

                    if(access(aux_ptr, X_OK) != 0) {

                        /* Let -1 mark cannot execute file */
                        arguments_counter = -1;
                        break;
                    }
                }
                arguments_counter++;
            }

            if(arguments_counter == -1) {

                fprintf(stderr, "ERROR: Cannot execute file\n");
                free(original_ptr);
                fclose(rules_file);
                close(process_fd);
                exit(1);
            } else if(arguments_counter != 3) {

                fprintf(stderr, "ERROR: Ill-formed file\n");
                free(original_ptr);
                fclose(rules_file);
                close(process_fd);
                exit(1);
            }
            free(original_ptr);
        }

        /* If we reached this point, everything is valid */
        rewind(rules_file);
        while((getline(&firewall_rule_ptr, &length, rules_file)) != -1) {

                char* occurrence = strchr(firewall_rule_ptr, '\n');
                if(occurrence != NULL) {

                    occurrence[0] = '\0';
                }
                write(process_fd, firewall_rule_ptr, strlen(firewall_rule_ptr) + 1);
        }

        fclose(rules_file);
        close(process_fd);
        exit(0);
        /* Otherwise it is invalid */
    } else {

        fprintf(stderr, "Usage: %s L\n", argv[0]);
        fprintf(stderr, "Usage: %s W <rules file>\n", argv[0]);
        exit(1);
    }

    return 0;
}
