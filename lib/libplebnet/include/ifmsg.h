/* All call messages start with a request
 * All return messages start with an errno
 */


struct call_msg {
	int cm_size; /* size of data after call_msg if any */
	int cm_id;
};

struct return_msg {
	int rm_size; /* size of data after return_msg if any */
	int rm_errno;
};

/* 
 * ioctl messages
 */

struct ioctl_call_msg {
	int icm_fd;
	unsigned long icm_request;
	char icm_data[0];

};

struct ifreq_call_msg {
	int icm_fd;
	unsigned long icm_request;
	struct ifreq icm_ifr;
	char icm_ifr_data[0];
};

struct ifreq_return_msg {
	struct ifreq irm_ifr;
	char icm_ifr_data[0];
};


struct ifconf_call_msg {
	int icm_fd;
	unsigned long icm_request;
	int icm_ifc_len;
};

struct ifconf_return_msg {
	int irm_ifc_len;
	char irm_ifconf_data[0];
};


struct ifgroup_call_msg {
	int icm_fd;
	unsigned long icm_request;
	struct ifgroupreq icm_ifgrq;
	char icm_ifgrq_data[0];
};

struct ifgroup_return_msg {
	struct ifgroupreq irm_ifgrq;
	char irm_ifgrq_data[0];
};


struct ifclonereq_call_msg {
	int icm_fd;
	unsigned long icm_request;
	int icm_ifcr_count;
};

struct if_clonereq_return_msg {
	int ifcrm_total;
	char ifcrm_buffer[0];
};


/* other system calls */

struct socket_call_msg {
	int scm_domain; 
	int scm_type; 
	int scm_protocol;
};

struct socket_return_msg {
	int srm_fd;
};
