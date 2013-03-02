/*
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 *   * Neither the name of SWITCH nor the names of its contributors may be 
 *     used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 *  
 *  $Author: haag $
 *
 *  $Id: nffile_inline.c 40 2009-12-16 10:41:44Z haag $
 *
 *  $LastChangedRevision: 40 $
 *	
 */

/* 
 * nffile_inline.c is needed for daemon code as well as normal stdio code 
 * therefore a generic LogError is defined, which maps to the 
 * approriate logging channel - either stderr or syslog
 */
void LogError(char *format, ...);

static inline int CheckBufferSpace(nffile_t *nffile, size_t required);

static inline void AppendToBuffer(nffile_t *nffile, void *record, size_t required);

static inline void ExpandRecord_v2(common_record_t *input_record, extension_info_t *extension_info, exporter_info_record_t *exporter_info, master_record_t *output_record );

static void PackRecord(master_record_t *master_record, nffile_t *nffile);

static inline int CheckBufferSpace(nffile_t *nffile, size_t required) {

#ifdef DEVEL
//	printf("Buffer Size %u\n", nffile->block_header->size);
#endif
	// flush current buffer to disc
	if ( (nffile->block_header->size + required )  > WRITE_BUFFSIZE ) {

		// this should never happen, but catch it anyway
		if ( required > WRITE_BUFFSIZE ) {
			LogError("Required buffer size %zu too big for output buffer!" , required);
			return 0;
		}

		if ( WriteBlock(nffile) <= 0 ) {
			LogError("Failed to write output buffer to disk: '%s'" , strerror(errno));
			return 0;
		} 
	}

	return 1;
} // End of CheckBufferSpace


/*
 * Expand file record into master record for further processing
 * LP64 CPUs need special 32bit operations as it is not guarateed, that 64bit
 * values are aligned 
 */
static inline void ExpandRecord_v2(common_record_t *input_record, extension_info_t *extension_info, exporter_info_record_t *exporter_info, master_record_t *output_record ) {
extension_map_t *extension_map = extension_info->map;
uint32_t	i, *u;
size_t		size;
void		*p = (void *)input_record;

	// set map ref
	output_record->map_ref = extension_map;

	// Copy common data block
	size = COMMON_RECORD_DATA_SIZE;
	memcpy((void *)output_record, p, size);
	p = (void *)input_record->data;

	if ( exporter_info ) {
		uint32_t sysid = exporter_info->sysid;
		output_record->exporter_sysid = sysid;
		input_record->exporter_sysid  = sysid;
		output_record->exp_ref 		  = exporter_info;
	} else {
		output_record->exp_ref 		  = NULL;
	}

	// map icmp type/code in it's own vars
	output_record->icmp = output_record->dstport;

	// Required extension 1 - IP addresses
	if ( (input_record->flags & FLAG_IPV6_ADDR) != 0 )	{ // IPv6
		// IPv6
		memcpy((void *)output_record->v6.srcaddr, p, 4 * sizeof(uint64_t));	
		p = (void *)((pointer_addr_t)p + 4 * sizeof(uint64_t));
	} else { 	
		// IPv4
		u = (uint32_t *)p;
		output_record->v6.srcaddr[0] = 0;
		output_record->v6.srcaddr[1] = 0;
		output_record->v4.srcaddr 	 = u[0];

		output_record->v6.dstaddr[0] = 0;
		output_record->v6.dstaddr[1] = 0;
		output_record->v4.dstaddr 	 = u[1];
		p = (void *)((pointer_addr_t)p + 2 * sizeof(uint32_t));
	}

	// Required extension 2 - packet counter
	if ( (input_record->flags & FLAG_PKG_64 ) != 0 ) { 
		// 64bit packet counter
		value64_t	l, *v = (value64_t *)p;
		l.val.val32[0] = v->val.val32[0];
		l.val.val32[1] = v->val.val32[1];
		output_record->dPkts = l.val.val64;
		p = (void *)((pointer_addr_t)p + sizeof(uint64_t));
	} else {	
		// 32bit packet counter
		output_record->dPkts = *((uint32_t *)p);
		p = (void *)((pointer_addr_t)p + sizeof(uint32_t));
	}

	// Required extension 3 - byte counter
	if ( (input_record->flags & FLAG_BYTES_64 ) != 0 ) { 
		// 64bit byte counter
		value64_t	l, *v = (value64_t *)p;
		l.val.val32[0] = v->val.val32[0];
		l.val.val32[1] = v->val.val32[1];
		output_record->dOctets = l.val.val64;
		p = (void *)((pointer_addr_t)p + sizeof(uint64_t));
	} else {	
		// 32bit bytes counter
		output_record->dOctets = *((uint32_t *)p);
		p = (void *)((pointer_addr_t)p + sizeof(uint32_t));
	}

	// preset one single flow
	output_record->aggr_flows = 1;

	// Process optional extensions
	i=0;
	while ( extension_map->ex_id[i] ) {
		switch (extension_map->ex_id[i++]) {
			// 0 - 3 should never be in an extension table so - ignore it
			case 0:
			case 1:
			case 2:
			case 3:
				break;
			case EX_IO_SNMP_2: {
				tpl_ext_4_t *tpl = (tpl_ext_4_t *)p;
				output_record->input  = tpl->input;
				output_record->output = tpl->output;
				p = (void *)tpl->data;
				} break;
			case EX_IO_SNMP_4: {
				tpl_ext_5_t *tpl = (tpl_ext_5_t *)p;
				output_record->input  = tpl->input;
				output_record->output = tpl->output;
				p = (void *)tpl->data;
				} break;
			case EX_AS_2: {
				tpl_ext_6_t *tpl = (tpl_ext_6_t *)p;
				output_record->srcas = tpl->src_as;
				output_record->dstas = tpl->dst_as;
				p = (void *)tpl->data;
				} break;
			case EX_AS_4: {
				tpl_ext_7_t *tpl = (tpl_ext_7_t *)p;
				output_record->srcas = tpl->src_as;
				output_record->dstas = tpl->dst_as;
				p = (void *)tpl->data;
				} break;
			case EX_MULIPLE: {
				tpl_ext_8_t *tpl = (tpl_ext_8_t *)p;
				// use a 32 bit int to copy all 4 fields
				output_record->any = tpl->any;
				p = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_v4: {
				tpl_ext_9_t *tpl = (tpl_ext_9_t *)p;
				output_record->ip_nexthop.v6[0] = 0;
				output_record->ip_nexthop.v6[1] = 0;
				output_record->ip_nexthop.v4	= tpl->nexthop;
				p = (void *)tpl->data;
				ClearFlag(output_record->flags, FLAG_IPV6_NH);
				} break;
			case EX_NEXT_HOP_v6: {
				tpl_ext_10_t *tpl = (tpl_ext_10_t *)p;
				output_record->ip_nexthop.v6[0] = tpl->nexthop[0];
				output_record->ip_nexthop.v6[1] = tpl->nexthop[1];
				p = (void *)tpl->data;
				SetFlag(output_record->flags, FLAG_IPV6_NH);
				} break;
			case EX_NEXT_HOP_BGP_v4: {
				tpl_ext_11_t *tpl = (tpl_ext_11_t *)p;
				output_record->bgp_nexthop.v6[0] = 0;
				output_record->bgp_nexthop.v6[1] = 0;
				output_record->bgp_nexthop.v4	= tpl->bgp_nexthop;
				ClearFlag(output_record->flags, FLAG_IPV6_NHB);
				p = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_BGP_v6: {
				tpl_ext_12_t *tpl = (tpl_ext_12_t *)p;
				output_record->bgp_nexthop.v6[0] = tpl->bgp_nexthop[0];
				output_record->bgp_nexthop.v6[1] = tpl->bgp_nexthop[1];
				p = (void *)tpl->data;
				SetFlag(output_record->flags, FLAG_IPV6_NHB);
				} break;
			case EX_VLAN: {
				tpl_ext_13_t *tpl = (tpl_ext_13_t *)p;
				output_record->src_vlan = tpl->src_vlan;
				output_record->dst_vlan = tpl->dst_vlan;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_PKG_4: {
				tpl_ext_14_t *tpl = (tpl_ext_14_t *)p;
				output_record->out_pkts = tpl->out_pkts;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_PKG_8: {
				tpl_ext_15_t v, *tpl = (tpl_ext_15_t *)p;
				v.v[0] = tpl->v[0];
				v.v[1] = tpl->v[1];
				output_record->out_pkts = v.out_pkts;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_BYTES_4: {
				tpl_ext_16_t *tpl = (tpl_ext_16_t *)p;
				output_record->out_bytes = tpl->out_bytes;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_BYTES_8: {
				tpl_ext_17_t v,*tpl = (tpl_ext_17_t *)p;
				v.v[0] = tpl->v[0];
				v.v[1] = tpl->v[1];
				output_record->out_bytes = v.out_bytes;
				p = (void *)tpl->data;
				} break;
			case EX_AGGR_FLOWS_4: {
				tpl_ext_18_t *tpl = (tpl_ext_18_t *)p;
				output_record->aggr_flows = tpl->aggr_flows;
				p = (void *)tpl->data;
				} break;
			case EX_AGGR_FLOWS_8: {
				tpl_ext_19_t v, *tpl = (tpl_ext_19_t *)p;
				v.v[0] = tpl->v[0];
				v.v[1] = tpl->v[1];
				output_record->aggr_flows = v.aggr_flows;
				p = (void *)tpl->data;
				} break;
			case EX_MAC_1: {
				tpl_ext_20_t v, *tpl = (tpl_ext_20_t *)p;
				v.v1[0] = tpl->v1[0];
				v.v1[1] = tpl->v1[1];
				output_record->in_src_mac = v.in_src_mac;

				v.v2[0] = tpl->v2[0];
				v.v2[1] = tpl->v2[1];
				output_record->out_dst_mac = v.out_dst_mac;
				p = (void *)tpl->data;
				} break;
			case EX_MAC_2: {
				tpl_ext_21_t v, *tpl = (tpl_ext_21_t *)p;
				v.v1[0] = tpl->v1[0];
				v.v1[1] = tpl->v1[1];
				output_record->in_dst_mac = v.in_dst_mac;
				v.v2[0] = tpl->v2[0];
				v.v2[1] = tpl->v2[1];
				output_record->out_src_mac = v.out_src_mac;
				p = (void *)tpl->data;
				} break;
			case EX_MPLS: {
				tpl_ext_22_t *tpl = (tpl_ext_22_t *)p;
				int j;
				for (j=0; j<10; j++ ) {
					output_record->mpls_label[j] = tpl->mpls_label[j];
				}
				p = (void *)tpl->data;
			} break;
			case EX_ROUTER_IP_v4: {
				tpl_ext_23_t *tpl = (tpl_ext_23_t *)p;
				output_record->ip_router.v6[0] = 0;
				output_record->ip_router.v6[1] = 0;
				output_record->ip_router.v4	= tpl->router_ip;
				p = (void *)tpl->data;
				ClearFlag(output_record->flags, FLAG_IPV6_EXP);
				} break;
			case EX_ROUTER_IP_v6: {
				tpl_ext_24_t *tpl = (tpl_ext_24_t *)p;
				output_record->ip_router.v6[0] = tpl->router_ip[0];
				output_record->ip_router.v6[1] = tpl->router_ip[1];
				p = (void *)tpl->data;
				SetFlag(output_record->flags, FLAG_IPV6_EXP);
				} break;
			case EX_ROUTER_ID: {
				tpl_ext_25_t *tpl = (tpl_ext_25_t *)p;
				output_record->engine_type = tpl->engine_type;
				output_record->engine_id   = tpl->engine_id;
				p = (void *)tpl->data;
				} break;
			case EX_BGPADJ: {
				tpl_ext_26_t *tpl = (tpl_ext_26_t *)p;
				output_record->bgpNextAdjacentAS = tpl->bgpNextAdjacentAS;
				output_record->bgpPrevAdjacentAS = tpl->bgpPrevAdjacentAS;
				p = (void *)tpl->data;
			} break;
			case EX_LATENCY: {
				tpl_ext_latency_t *tpl = (tpl_ext_latency_t *)p;
				output_record->client_nw_delay_usec = tpl->client_nw_delay_usec;
				output_record->server_nw_delay_usec = tpl->server_nw_delay_usec;
				output_record->appl_latency_usec = tpl->appl_latency_usec;
				p = (void *)tpl->data;
			} break;
			case EX_RECEIVED: {
				tpl_ext_27_t *tpl = (tpl_ext_27_t *)p;
				output_record->received = tpl->received;
				p = (void *)tpl->data;
			} break;
#ifdef NSEL
			case EX_NSEL_COMMON: {
				tpl_ext_37_t *tpl = (tpl_ext_37_t *)p;
				output_record->flow_start = tpl->flow_start;
				output_record->conn_id 	  = tpl->conn_id;
				output_record->fw_event   = tpl->fw_event;
				output_record->fw_xevent  = tpl->fw_xevent;
				output_record->icmp = tpl->nsel_icmp;
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_XLATE_PORTS: {
				tpl_ext_38_t *tpl = (tpl_ext_38_t *)p;
				output_record->xlate_src_port = tpl->xlate_src_port;
				output_record->xlate_dst_port = tpl->xlate_dst_port;
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_XLATE_IP_v4: {
				tpl_ext_39_t *tpl = (tpl_ext_39_t *)p;
				output_record->xlate_src_ip.v6[0] = 0;
				output_record->xlate_src_ip.v6[1] = 0;
				output_record->xlate_src_ip.v4	= tpl->xlate_src_ip;
				output_record->xlate_dst_ip.v6[0] = 0;
				output_record->xlate_dst_ip.v6[1] = 0;
				output_record->xlate_dst_ip.v4	= tpl->xlate_dst_ip;
				p = (void *)tpl->data;
				output_record->xlate_flags = 0;
				} break;
			case EX_NSEL_XLATE_IP_v6: {
				tpl_ext_40_t *tpl = (tpl_ext_40_t *)p;
				output_record->xlate_src_ip.v6[0] = tpl->xlate_src_ip[0];
				output_record->xlate_src_ip.v6[1] = tpl->xlate_src_ip[1];
				output_record->xlate_dst_ip.v6[0] = tpl->xlate_dst_ip[0];
				output_record->xlate_dst_ip.v6[1] = tpl->xlate_dst_ip[1];
				p = (void *)tpl->data;
				output_record->xlate_flags = 1;
				} break;
			case EX_NSEL_ACL: {
				tpl_ext_41_t *tpl = (tpl_ext_41_t *)p;
				int j;
				for (j=0; j<3; j++) {
					output_record->ingress_acl_id[j] = tpl->ingress_acl_id[j];
					output_record->egress_acl_id[j] = tpl->egress_acl_id[j];
				}
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_USER: {
				tpl_ext_42_t *tpl = (tpl_ext_42_t *)p;
				strncpy((void *)output_record->username, (void *)tpl->username, sizeof(output_record->username));
				output_record->username[sizeof(output_record->username)-1] = '\0';	// safety 0
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_USER_MAX: {
				tpl_ext_43_t *tpl = (tpl_ext_43_t *)p;
				strncpy((void *)output_record->username, (void *)tpl->username, sizeof(output_record->username));
				output_record->username[sizeof(output_record->username)-1] = '\0';	// safety 0
				p = (void *)tpl->data;
			} break;
#endif
#ifdef NEL
			case EX_NEL_COMMON: {
				tpl_ext_46_t *tpl = (tpl_ext_46_t *)p;
				output_record->nat_event = tpl->nat_event;
				output_record->post_src_port = tpl->post_src_port;
				output_record->post_dst_port = tpl->post_dst_port;
				output_record->ingress_vrfid = tpl->ingress_vrfid;
				p = (void *)tpl->data;
			} break;
			case EX_NEL_GLOBAL_IP_v4: {
				tpl_ext_47_t *tpl = (tpl_ext_47_t *)p;
				output_record->nat_inside.v6[0] = 0;
				output_record->nat_inside.v6[1] = 0;
				output_record->nat_inside.v4	= tpl->nat_inside;
				output_record->nat_outside.v6[0] = 0;
				output_record->nat_outside.v6[1] = 0;
				output_record->nat_outside.v4	= tpl->nat_outside;
				p = (void *)tpl->data;
				output_record->nat_flags = 0;
				} break;
			case EX_NEL_GLOBAL_IP_v6: {
				tpl_ext_48_t *tpl = (tpl_ext_48_t *)p;
				output_record->nat_inside.v6[0] = tpl->nat_inside[0];
				output_record->nat_inside.v6[1] = tpl->nat_inside[1];
				output_record->nat_outside.v6[0] = tpl->nat_outside[0];
				output_record->nat_outside.v6[1] = tpl->nat_outside[1];
				p = (void *)tpl->data;
				output_record->nat_flags = 1;
				} break;
#endif
		}
	}
	
} // End of ExpandRecord_v2

static void PackRecord(master_record_t *master_record, nffile_t *nffile) {
extension_map_t *extension_map = master_record->map_ref;
uint32_t required =  COMMON_RECORD_DATA_SIZE + extension_map->extension_size;
size_t	 size;
void	 *p;
int		i;

	// check size of packets and bytes
	if ( master_record->dPkts >  0xffffffffLL ) {
		master_record->flags |= FLAG_PKG_64;
		required += 8;
	} else {
		master_record->flags &= ~FLAG_PKG_64;
		required += 4;
	}

	if ( master_record->dOctets >  0xffffffffLL ) {
		master_record->flags |= FLAG_BYTES_64;
		required += 8;
	} else {
		master_record->flags &= ~FLAG_BYTES_64;
		required += 4;
	}
	if ( (master_record->flags & FLAG_IPV6_ADDR) != 0 )	// IPv6
		required += 32;
	else
		required += 8;

	master_record->size = required;

	// flush current buffer to disc if not enough space
	if ( !CheckBufferSpace(nffile, required) ) {
		return;
	}

	// enough buffer space available at this point
	p = nffile->buff_ptr;

	// write common record
	size = COMMON_RECORD_DATA_SIZE;
	memcpy(p, (void *)master_record, size);
	p = (void *)((pointer_addr_t)p + size);

	// Required extension 1 - IP addresses
	if ( (master_record->flags & FLAG_IPV6_ADDR) != 0 )	{ // IPv6
		// IPv6
		memcpy(p, (void *)master_record->v6.srcaddr, 4 * sizeof(uint64_t));	
		p = (void *)((pointer_addr_t)p + 4 * sizeof(uint64_t));
	} else { 	
		// IPv4
		uint32_t *u = (uint32_t *)p;
		u[0] = master_record->v4.srcaddr;
		u[1] = master_record->v4.dstaddr;
		p = (void *)((pointer_addr_t)p + 2 * sizeof(uint32_t));
	}

	// Required extension 2 - packet counter
	if ( (master_record->flags & FLAG_PKG_64 ) != 0 ) { 
		// 64bit packet counter
		value64_t	l, *v = (value64_t *)p;
		l.val.val64 = master_record->dPkts;
		v->val.val32[0] = l.val.val32[0];
		v->val.val32[1] = l.val.val32[1];
		p = (void *)((pointer_addr_t)p + sizeof(uint64_t));
	} else {	
		// 32bit packet counter
		*((uint32_t *)p) = master_record->dPkts;
		p = (void *)((pointer_addr_t)p + sizeof(uint32_t));
	}

	// Required extension 3 - byte counter
	if ( (master_record->flags & FLAG_BYTES_64 ) != 0 ) { 
		// 64bit byte counter
		value64_t	l, *v = (value64_t *)p;
		l.val.val64 = master_record->dOctets;
		v->val.val32[0] = l.val.val32[0];
		v->val.val32[1] = l.val.val32[1];
		p = (void *)((pointer_addr_t)p + sizeof(uint64_t));
	} else {	
		// 32bit bytes counter
		*((uint32_t *)p) = master_record->dOctets;
		p = (void *)((pointer_addr_t)p + sizeof(uint32_t));
	}

	// Process optional extensions
	i=0;
	while ( extension_map->ex_id[i] ) {
		switch (extension_map->ex_id[i++]) {
			// 0 - 3 should never be in an extension table so - ignore it
			case 0:
			case 1:
			case 2:
			case 3:
				break;
			case EX_IO_SNMP_2: { // input/output SNMP 2 byte
				tpl_ext_4_t *tpl = (tpl_ext_4_t *)p;
				tpl->input  = master_record->input;
				tpl->output = master_record->output;
				p = (void *)tpl->data;
				} break;
			case EX_IO_SNMP_4: { // input/output SNMP 4 byte
				tpl_ext_5_t *tpl = (tpl_ext_5_t *)p;
				tpl->input  = master_record->input;
				tpl->output = master_record->output;
				p = (void *)tpl->data;
				} break;
			case EX_AS_2: { // srcas/dstas 2 byte
				tpl_ext_6_t *tpl = (tpl_ext_6_t *)p;
				tpl->src_as = master_record->srcas;
				tpl->dst_as = master_record->dstas;
				p = (void *)tpl->data;
				} break;
			case EX_AS_4: { // srcas/dstas 4 byte
				tpl_ext_7_t *tpl = (tpl_ext_7_t *)p;
				tpl->src_as = master_record->srcas;
				tpl->dst_as = master_record->dstas;
				p = (void *)tpl->data;
				} break;
			case EX_MULIPLE: {
				tpl_ext_8_t *tpl = (tpl_ext_8_t *)p;
				// use a 32 bit int to copy all 4 fields
				tpl->any = master_record->any;
				p = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_v4: {
				tpl_ext_9_t *tpl = (tpl_ext_9_t *)p;
				tpl->nexthop = master_record->ip_nexthop.v4;
				p = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_v6: {
				tpl_ext_10_t *tpl = (tpl_ext_10_t *)p;
				tpl->nexthop[0] = master_record->ip_nexthop.v6[0];
				tpl->nexthop[1] = master_record->ip_nexthop.v6[1];
				p = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_BGP_v4: {
				tpl_ext_11_t *tpl = (tpl_ext_11_t *)p;
				tpl->bgp_nexthop = master_record->bgp_nexthop.v4;
				p = (void *)tpl->data;
				} break;
			case EX_NEXT_HOP_BGP_v6: {
				tpl_ext_12_t *tpl = (tpl_ext_12_t *)p;
				tpl->bgp_nexthop[0] = master_record->bgp_nexthop.v6[0];
				tpl->bgp_nexthop[1] = master_record->bgp_nexthop.v6[1];
				p = (void *)tpl->data;
				} break;
			case EX_VLAN: {
				tpl_ext_13_t *tpl = (tpl_ext_13_t *)p;
				tpl->src_vlan = master_record->src_vlan;
				tpl->dst_vlan = master_record->dst_vlan;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_PKG_4: {
				tpl_ext_14_t *tpl = (tpl_ext_14_t *)p;
				tpl->out_pkts = master_record->out_pkts;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_PKG_8: {
				tpl_ext_15_t v, *tpl = (tpl_ext_15_t *)p;
				v.out_pkts = master_record->out_pkts;
				tpl->v[0] = v.v[0];
				tpl->v[1] = v.v[1];
				p = (void *)tpl->data;
				} break;
			case EX_OUT_BYTES_4: {
				tpl_ext_16_t *tpl = (tpl_ext_16_t *)p;
				tpl->out_bytes = master_record->out_bytes;
				p = (void *)tpl->data;
				} break;
			case EX_OUT_BYTES_8: {
				tpl_ext_17_t v, *tpl = (tpl_ext_17_t *)p;
				v.out_bytes = master_record->out_bytes;
				tpl->v[0] = v.v[0];
				tpl->v[1] = v.v[1];
				p = (void *)tpl->data;
				} break;
			case EX_AGGR_FLOWS_4: {
				tpl_ext_18_t *tpl = (tpl_ext_18_t *)p;
				tpl->aggr_flows = master_record->aggr_flows;
				p = (void *)tpl->data;
				} break;
			case EX_AGGR_FLOWS_8: {
				tpl_ext_19_t v, *tpl = (tpl_ext_19_t *)p;
				v.aggr_flows = master_record->aggr_flows;
				tpl->v[0] = v.v[0];
				tpl->v[1] = v.v[1];
				p = (void *)tpl->data;
				} break;
			case EX_MAC_1: {
				tpl_ext_20_t v, *tpl = (tpl_ext_20_t *)p;
				v.in_src_mac = master_record->in_src_mac;
				tpl->v1[0] = v.v1[0];
				tpl->v1[1] = v.v1[1];
				v.out_dst_mac = master_record->out_dst_mac;
				tpl->v2[0] = v.v2[0];
				tpl->v2[1] = v.v2[1];
				p = (void *)tpl->data;
				} break;
			case EX_MAC_2: {
				tpl_ext_21_t v, *tpl = (tpl_ext_21_t *)p;
				v.in_dst_mac = master_record->in_dst_mac;
				tpl->v1[0] = v.v1[0];
				tpl->v1[1] = v.v1[1];
				v.out_src_mac = master_record->out_src_mac;
				tpl->v2[0] = v.v2[0];
				tpl->v2[1] = v.v2[1];
				p = (void *)tpl->data;
				} break;
			case EX_MPLS: {
				tpl_ext_22_t *tpl = (tpl_ext_22_t *)p;
				int j;
				for (j=0; j<10; j++ ) {
					tpl->mpls_label[j] = master_record->mpls_label[j];
				}
				p = (void *)tpl->data;
				} break;
			case EX_ROUTER_IP_v4: {
				tpl_ext_23_t *tpl = (tpl_ext_23_t *)p;
				tpl->router_ip = master_record->ip_router.v4;
				p = (void *)tpl->data;
				} break;
			case EX_ROUTER_IP_v6: {
				tpl_ext_24_t *tpl = (tpl_ext_24_t *)p;
				tpl->router_ip[0] = master_record->ip_router.v6[0];
				tpl->router_ip[1] = master_record->ip_router.v6[1];
				p = (void *)tpl->data;
				} break;
			case EX_ROUTER_ID: {
				tpl_ext_25_t *tpl = (tpl_ext_25_t *)p;
				tpl->engine_type = master_record->engine_type;
				tpl->engine_id   = master_record->engine_id;
				p = (void *)tpl->data;
				} break;
			case EX_BGPADJ: {
				tpl_ext_26_t *tpl = (tpl_ext_26_t *)p;
				tpl->bgpNextAdjacentAS = master_record->bgpNextAdjacentAS;
				tpl->bgpPrevAdjacentAS = master_record->bgpPrevAdjacentAS;
				p = (void *)tpl->data;
				} break;
			case EX_RECEIVED: {
				tpl_ext_27_t *tpl = (tpl_ext_27_t *)p;
				tpl->received = master_record->received;
				p = (void *)tpl->data;
				} break;
#ifdef NSEL
			case EX_NSEL_COMMON: {
				tpl_ext_37_t *tpl = (tpl_ext_37_t *)p;
				tpl->flow_start = master_record->flow_start;
				tpl->conn_id    = master_record->conn_id;
				tpl->fw_event   = master_record->fw_event;
				tpl->nsel_icmp  = master_record->icmp;
				tpl->fill  = 0;
				tpl->fill2 = 0;
				tpl->fw_xevent = master_record->fw_xevent;
				p = (void *)tpl->data;
				} break;
			case EX_NSEL_XLATE_PORTS: {
				tpl_ext_38_t *tpl = (tpl_ext_38_t *)p;
				tpl->xlate_src_port	 = master_record->xlate_src_port;
				tpl->xlate_dst_port	 = master_record->xlate_dst_port;
				p = (void *)tpl->data;
				} break;
			case EX_NSEL_XLATE_IP_v4: {
				tpl_ext_39_t *tpl = (tpl_ext_39_t *)p;
				tpl->xlate_src_ip = master_record->xlate_src_ip.v4;
				tpl->xlate_dst_ip = master_record->xlate_dst_ip.v4;
				p = (void *)tpl->data;
				} break;
			case EX_NSEL_XLATE_IP_v6: {
				tpl_ext_40_t *tpl = (tpl_ext_40_t *)p;
				tpl->xlate_src_ip[0] = master_record->xlate_src_ip.v6[0];
				tpl->xlate_src_ip[1] = master_record->xlate_src_ip.v6[1];
				p = (void *)tpl->data;
				tpl->xlate_dst_ip[0] = master_record->xlate_dst_ip.v6[0];
				tpl->xlate_dst_ip[1] = master_record->xlate_dst_ip.v6[1];
				p = (void *)tpl->data;
				} break;
			case EX_NSEL_ACL: {
				tpl_ext_41_t *tpl = (tpl_ext_41_t *)p;
				int j;
				for (j=0; j<3; j++) {
					tpl->ingress_acl_id[j] = master_record->ingress_acl_id[j];
					tpl->egress_acl_id[j]  = master_record->egress_acl_id[j];
				}
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_USER: {
				tpl_ext_42_t *tpl = (tpl_ext_42_t *)p;
				strncpy((void *)tpl->username, (void *)master_record->username, sizeof(tpl->username));
				tpl->username[sizeof(tpl->username)-1] = '\0';	// safety 0
				p = (void *)tpl->data;
			} break;
			case EX_NSEL_USER_MAX: {
				tpl_ext_43_t *tpl = (tpl_ext_43_t *)p;
				strncpy((void *)tpl->username, (void *)master_record->username, sizeof(tpl->username));
				tpl->username[sizeof(tpl->username)-1] = '\0';	// safety 0
				p = (void *)tpl->data;
			} break;
#endif
#ifdef NEL
			case EX_NEL_COMMON: {
				tpl_ext_46_t *tpl = (tpl_ext_46_t *)p;
				tpl->nat_event  = master_record->nat_event;
				tpl->fill  = 0;
				tpl->flags = 0;
				tpl->post_src_port	 = master_record->post_src_port;
				tpl->post_dst_port	 = master_record->post_dst_port;
				tpl->ingress_vrfid   = master_record->ingress_vrfid;
				p = (void *)tpl->data;
				} break;
			case EX_NEL_GLOBAL_IP_v4: {
				tpl_ext_47_t *tpl = (tpl_ext_47_t *)p;
				tpl->nat_inside = master_record->nat_inside.v4;
				tpl->nat_outside = master_record->nat_outside.v4;
				p = (void *)tpl->data;
				} break;
			case EX_NEL_GLOBAL_IP_v6: {
				tpl_ext_48_t *tpl = (tpl_ext_48_t *)p;
				tpl->nat_inside[0] = master_record->nat_inside.v6[0];
				tpl->nat_inside[1] = master_record->nat_inside.v6[1];
				p = (void *)tpl->data;
				tpl->nat_outside[0] = master_record->nat_outside.v6[0];
				tpl->nat_outside[1] = master_record->nat_outside.v6[1];
				p = (void *)tpl->data;
				} break;
#endif
		}
	}

	nffile->block_header->size 		+= required;
	nffile->block_header->NumRecords++;
#ifdef DEVEL
	if ( ((pointer_addr_t)p - (pointer_addr_t)nffile->buff_ptr) != required ) {
		fprintf(stderr, "Packrecord: size missmatch: required: %i, written: %li!\n", 
			required, (long)((ptrdiff_t)p - (ptrdiff_t)nffile->buff_ptr));
		exit(255);
	}
#endif
	nffile->buff_ptr = p;

} // End of PackRecord

static inline void AppendToBuffer(nffile_t *nffile, void *record, size_t required) {

	// flush current buffer to disc
	if ( !CheckBufferSpace(nffile, required)) {
		return;
	}

	// enough buffer space available at this point
	memcpy(nffile->buff_ptr, record, required);

	// update stat
	nffile->block_header->NumRecords++;
	nffile->block_header->size += required;

	// advance write pointer
	nffile->buff_ptr = (void *)((pointer_addr_t)nffile->buff_ptr + required);

} // End of AppendToBuffer
