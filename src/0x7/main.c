#include <stdlib.h>
#include <stdio.h>

enum opts {
  OPTS_EDIT = 1,
  OPTS_READ = 2,
  OPTS_DEL  = 3,
  OPTS_EXIT = 4,
};

#define NOTE_SIZE 32
#define NOTE_MAX  10
char *notes[NOTE_MAX];

int note_get(char **note) {
  int i = 0;

  printf("Please enter the number of the node: ");
  scanf("%d", &i);

  if (i < 1 || i > NOTE_MAX) {
    printf("Invalid note number, please enter a number between 1 and %d\n", NOTE_MAX);
    return -1;
  }

  --i;

  if (NULL != note)
    *note = notes[i];

  return i;
}

int print_menu() {
  int opt = 0;

  puts("==== Secure Notes ====");
  puts("1. Add/edit a note");
  puts("2. Read a note");
  puts("3. Delete a note");
  puts("4. Quit");

  printf("Please select an option: ");
  scanf("%d", &opt);

  return opt;
}

void opt_edit() {
  int i = 0;

  if ((i = note_get(NULL)) < 0)
    return;

  if (NULL == notes[i])
    notes[i] = malloc(NOTE_SIZE);

  puts("Please enter your note");
  scanf("%s", notes[i]);
}

void opt_read() {
  char *note = NULL;

  if (note_get(&note) < 0)
    return;

  puts("----------------------");
  printf(note);
  puts("\n----------------------");
}

void opt_del() {
  int i = 0;

  if ((i = note_get(NULL)) < 0)
    return;

  free(notes[i]);
}

int main() {
  int opt = 0;

  while (1) {
    switch (opt = print_menu()) {
    case OPTS_EDIT:
      opt_edit();
      break;

    case OPTS_READ:
      opt_read();
      break;

    case OPTS_DEL:
      opt_del();
      break;

    case OPTS_EXIT:
      return 0;

    default:
      printf("Invalid option: %d\n", opt);
      break;
    }
  }
}
