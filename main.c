#include <linux/module.h>
int my_module_init(void)
{
  printk("Hello world!\n");
  return 0;
}
void my_module_cleanup(void)
{
  printk("Goodbye world!\n");
  return;
}
module_init(my_module_init);
module_exit(my_module_cleanup);
