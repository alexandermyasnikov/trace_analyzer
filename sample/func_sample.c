
#include <stdio.h>
#include <unistd.h>
#include "func.h"

int main() {
  sleep(5);

  int ret;

  for (int i = 0; i < 10000; ++i) {
    {
      ret = sum2(10, i);
      fprintf(stdout, "func(...) return : %d \n", ret);
    }

    {
      ret = sum3(11, i);
      fprintf(stdout, "func(...) return : %d \n", ret);
    }

    {
      struct char4_t char4 = {
        .a = 12,
        .b = 1,
        .c = 2,
        .d = i,
      };

      ret = test_char4_1(char4);
      fprintf(stdout, "func(...) return : %d \n", ret);
    }

    {
      struct char4_t char4 = {
        .a = 13,
        .b = -2,
        .c = 3,
        .d = i,
      };

      ret = test_char4_2(&char4);
      fprintf(stdout, "func(...) return : %d \n", ret);
    }

    {
      struct s4_t s4 = {
        .a = 14,
        .b = -1,
        .c = 2,
        .d = i,
      };

      ret = test_s4_1(s4);
      fprintf(stdout, "func(...) return : %d \n", ret);
    }

    {
      struct s4_t s4 = {
        .a = 15,
        .b = 1,
        .c = 2,
        .d = i,
      };

      ret = test_s4_2(&s4);
      fprintf(stdout, "func(...) return : %d \n", ret);
    }

    {
      ret = test_args(16, 2, 3, 4, 5, 6, 7, 8, 9, i);
      fprintf(stdout, "func(...) return : %d \n", ret);
    }

    sleep(3);
  }

  return 0;
}

