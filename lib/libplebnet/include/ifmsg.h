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

}__attribute__((packed));

struct ifreq_call_msg {
	int icm_fd;
	unsigned long icm_request;
	struct ifreq icm_ifr;
	char icm_ifr_data[0];
}__attribute__((packed));

struct ifreq_return_msg {
	struct ifreq irm_ifr;
	char icm_ifr_data[0];
};


struct ifconf_call_msg {
	int icm_fd;
	unsigned long icm_request;
	int icm_ifc_len;
}__attribute__((packed));

struct ifconf_return_msg {
	int irm_ifc_len;
	char irm_ifconf_data[0];
};

struct ifgroup_call_msg {
	int icm_fd;
	unsigned long icm_request;
	struct ifgroupreq icm_ifgrq;
	char icm_ifgrq_data[0];
}__attribute__((packed));

struct ifgroup_return_msg {
	struct ifgroupreq irm_ifgrq;
	char irm_ifgrq_data[0];
};

struct ifclonereq_call_msg {
	int icm_fd;
	unsigned long icm_request;
	int icm_ifcr_count;
}__attribute__((packed));

struct ifclonereq_return_msg {
	int irm_total;
	char irm_buffer[0];
};

struct ifmediareq_call_msg {
	int icm_fd;
	unsigned long icm_request;
	struct ifmediareq icm_ifmr;
}__attribute__((packed));

struct ifmediareq_return_msg {
	struct ifmediareq icm_ifmr;
	char icm_ifmr_data[0];
};

/* other system calls */

struct socket_call_msg {
	int scm_domain; 
	int scm_type; 
	int scm_protocol;
}__attribute__((packed));

struct socket_return_msg {
	int srm_fd;
};
