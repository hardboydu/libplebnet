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
}__attribute__((packed));

struct ifconf_call_msg {
	int icm_fd;
	unsigned long icm_request;
	int icm_ifc_len;
}__attribute__((packed));

struct ifconf_return_msg {
	int irm_ifc_len;
	char irm_ifconf_data[0];
}__attribute__((packed));

struct ifgroup_call_msg {
	int icm_fd;
	unsigned long icm_request;
	struct ifgroupreq icm_ifgrq;
	char icm_ifgrq_data[0];
}__attribute__((packed));

struct ifgroup_return_msg {
	struct ifgroupreq irm_ifgrq;
	char irm_ifgrq_data[0];
}__attribute__((packed));

struct ifclonereq_call_msg {
	int icm_fd;
	unsigned long icm_request;
	int icm_ifcr_count;
}__attribute__((packed));

struct ifclonereq_return_msg {
	int irm_total;
	char irm_buffer[0];
}__attribute__((packed));

struct ifmediareq_call_msg {
	int icm_fd;
	unsigned long icm_request;
	struct ifmediareq icm_ifmr;
}__attribute__((packed));

struct ifmediareq_return_msg {
	struct ifmediareq icm_ifmr;
	char icm_ifmr_data[0];
}__attribute__((packed));

/* other system calls */

struct socket_call_msg {
	int scm_domain; 
	int scm_type; 
	int scm_protocol;
}__attribute__((packed));

struct socket_return_msg {
	int srm_fd;
};

struct sysctl_call_msg {
	int scm_miblen; /* size of mib array in terms of sizeof(int) */
	size_t scm_oldlen;
	size_t scm_newlen;
	char scm_data[0];
}__attribute__((packed));

struct sysctl_return_msg {
	size_t srm_oldlen;
	char srm_data[0];
}__attribute__((packed));


struct in6_ndireq_call_msg {
	int incm_fd;
	unsigned long incm_request;
	struct in6_ndireq incm_ndi;
}__attribute__((packed));

struct in6_ndireq_return_msg {
	struct in6_ndireq inrm_ndi;
};

struct write_call_msg {
	int wcm_fd;
	char wcm_data[0];
}__attribute__((packed));

struct shutdown_call_msg {
	int scm_fd;
	int scm_how;
}__attribute__((packed));


struct kldid_msg {
	int kim_fileid;
}__attribute__((packed));

struct kldstat_return_msg {
	struct kld_file_stat ks_stat;
}__attribute__((packed));

struct kldunloadf_call_msg {
	int kucm_fileid;
	int kucm_flags;
}__attribute__((packed));
