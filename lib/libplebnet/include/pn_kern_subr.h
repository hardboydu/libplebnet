
int kern_socket(struct thread *td, struct socket_call_msg *uap);
int kern_ioctl(struct thread *td, int fd, u_long com, caddr_t data);
