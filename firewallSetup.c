#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#define BUFFERSIZE 512

int file_exists(char *filepath)
{
  if (access(filepath, F_OK) == 0)
    return 1;
  else
    return 0;
}

int is_executable(char *filepath)
{
  struct stat sb;
  if(stat(filepath, &sb) == 0 && sb.st_mode & S_IXOTH) 
    return 1;
  else 
    return 0;
}

char* parse_rules(char *filename)
{
  FILE *fp;
  struct stat sb;
  char *fb;
  char line[BUFFERSIZE];
 
  /* Open the rules file for reading */
  fp = fopen (filename, "r");
  if (fp == NULL) {
    fprintf (stderr, "Could not open rules file!\n");
    goto file_error;
  }

  /* Use stat to get the size of the file */
  if (stat(filename, &sb) != 0)
    goto malloc_error; 
  
  /* Allocate a buffer of that size */
  fb = calloc(sb.st_size, 1);
  if (fb == NULL)
    goto malloc_error;

  /* Read it line-by-line */
  while (fgets(line, BUFFERSIZE, fp) != NULL) {
    int port;
    char program[BUFFERSIZE];

    /* Scan each line for the correct format */
    if (sscanf(line, "%i %512s\n", &port, program) != 2){
      printf("ERROR: Ill-formed file\n");
      goto error;
    }
    if(!is_executable(program)) {
	    printf("ERROR: Cannot execute file\n");
	    goto error;
    }
    /* We don't need strncat because line must be shorter than fb */
    /* fb is the whole size of the file */
    strcat(fb, line);
  }
  fclose(fp);
  return fb;

 error:
  free(fb);
 malloc_error:
  fclose(fp);
 file_error: 
  return NULL;
}

int main (int argc, char **argv) {

  if (argc == 2 && strncmp(argv[1], "L", 2) == 0){ /* Exactly 2 args in 'L' mode */
    int proc_fd;

    proc_fd = open("/proc/firewallExtension", O_RDONLY);
    if (proc_fd == -1) {
      printf("Could not open /proc/firewallExtensoin\n");
      return -1;
    }
    ioctl(proc_fd, 0, NULL);
    close(proc_fd);
    return 0;
  
  } else if (argc == 3 && strncmp(argv[1], "W", 2) == 0) { /* Exeactly 3 args in 'W' mode */
    FILE *proc_fp;
    char *rules;
    /* copy filename into buffer */
    char filename[BUFFERSIZE];
    strncpy(filename, argv[2], BUFFERSIZE);
    filename[BUFFERSIZE-1] = '\0'; /* strncpy can give a non null-terminated string */
    
    rules = parse_rules(filename);
    if (rules == NULL) {
      return -1;
    }

    proc_fp = fopen("/proc/firewallExtension", "w");
    if (proc_fp == NULL) {
      printf("Could not open /proc/firewallExtension\n");
      return -1;
    }

    fwrite(rules, 1, strlen(rules), proc_fp);
    fclose(proc_fp);
    free(rules);
    return 0;
  } else {
    fprintf(stderr, "Usage: \tfirewallSetup L\n\tfirewallSetup W <filepath>\n");
    exit(1);
  }

  return 0;
}


