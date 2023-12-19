#include <stddef.h>
#include <stdint.h>

struct platform_socket;

struct platform_socket *platform_create_socket();
int platform_socket_bind(const char *l_addr, u_int16_t l_port);
int platform_socket_connect(struct platform_socket *sock, const char *r_addr, u_int16_t r_port);
int platform_socket_finish_connect(struct platform_socket *sock, struct rust_async_waker *waker);
int platform_read_socket(struct platform_socket *sock, struct rust_async_waker *waker, void *buffer, size_t buffer_len, size_t *bytes_read);
int platform_write_socket(struct platform_socket *sock, struct rust_async_waker *waker, void *buffer, size_t buffer_len, size_t *bytes_written);
int platform_shutdown_socket(struct platform_socket *sock, struct rust_async_waker *waker);
void platform_close_socket(struct platform_socket *sock);
void platform_free_socket(struct platform_socket *sock);

struct platform_socket_info;

struct platform_socket_info *platform_get_socket_info(struct platform_socket *sock);
int platform_get_socket_af(struct platform_socket_info *sock_info);
const char *platform_get_socket_l_addr(struct platform_socket_info *sock_info);
uint16_t platform_get_socket_l_port(struct platform_socket_info *sock_info);
void platform_free_socket_info(struct platform_socket_info *sock_info);

struct platform_cipher_suite;

struct platform_cipher_suite *platform_get_socket_session_cipher_suite(struct platform_socket *sock);
uint8_t platform_cipher_suite_get_yy(struct platform_cipher_suite *cipher_suite);
uint8_t platform_cipher_suite_get_zz(struct platform_cipher_suite *cipher_suite);
void platform_free_cipher_suite(struct platform_cipher_suite *cipher_suite);