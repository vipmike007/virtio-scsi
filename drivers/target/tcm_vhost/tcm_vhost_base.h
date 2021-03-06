#define TCM_VHOST_VERSION  "v0.1"
#define TCM_VHOST_NAMELEN 256
#define TCM_VHOST_MAX_CDB_SIZE 32

struct tcm_vhost_cmd {
	/* Descriptor from vhost_get_vq_desc() for virt_queue segment */
	int tvc_vq_desc;
	/* The Tag from include/linux/virtio_scsi.h:struct virtio_scsi_cmd_header */
	u64 tvc_tag;
	/* The number of scatterlists associated with this cmd */
	u32 tvc_sgl_count;
	/* Pointer to the SGL formatted memory from virtio-scsi */
	struct scatterlist *tvc_sgl;
	/* Pointer to response */
	struct virtio_scsi_cmd_resp __user *tvc_cmd_resp;
	/* Pointer to vhost_scsi for our device */
	struct vhost_scsi *tvc_vhost;
	 /* The TCM I/O descriptor that is accessed via container_of() */
	struct se_cmd tvc_se_cmd;
	/* Copy of the incoming SCSI command descriptor block (CDB) */
	unsigned char tvc_cdb[TCM_VHOST_MAX_CDB_SIZE];
	/* Sense buffer that will be mapped into outgoing status */
	unsigned char tvc_sense_buf[TRANSPORT_SENSE_BUFFER];
	/* Completed commands list, serviced from vhost worker thread */
	struct list_head tvc_completion_list;
};

struct tcm_vhost_nexus {
	/* Pointer to TCM session for I_T Nexus */
	struct se_session *tvn_se_sess;
};

struct tcm_vhost_nacl {
	/* Binary World Wide unique Port Name for Vhost Initiator port */
	u64 iport_wwpn;
	/* ASCII formatted WWPN for Sas Initiator port */
	char iport_name[TCM_VHOST_NAMELEN];
	/* Returned by tcm_vhost_make_nodeacl() */
	struct se_node_acl se_node_acl;
};

struct tcm_vhost_tpg {
	/* Vhost port target portal group tag for TCM */
	u16 tport_tpgt;
	/* Used to track number of TPG Port/Lun Links wrt to explict I_T Nexus shutdown */
	atomic_t tv_tpg_port_count;
	/* Used for vhost_scsi device reference to tpg_nexus */
	atomic_t tv_tpg_vhost_count;
	/* list for tcm_vhost_list */
	struct list_head tv_tpg_list;
	/* Used to protect access for tpg_nexus */
	struct mutex tv_tpg_mutex;
	/* Pointer to the TCM VHost I_T Nexus for this TPG endpoint */
	struct tcm_vhost_nexus *tpg_nexus;
	/* Pointer back to tcm_vhost_tport */
	struct tcm_vhost_tport *tport;
	/* Returned by tcm_vhost_make_tpg() */
	struct se_portal_group se_tpg;
};

struct tcm_vhost_tport {
	/* SCSI protocol the tport is providing */
	u8 tport_proto_id;
	/* Binary World Wide unique Port Name for Vhost Target port */
	u64 tport_wwpn;
	/* ASCII formatted WWPN for Vhost Target port */
	char tport_name[TCM_VHOST_NAMELEN];
	/* Returned by tcm_vhost_make_tport() */
	struct se_wwn tport_wwn;
};
