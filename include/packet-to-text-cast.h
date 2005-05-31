char *str_from_map(int packet_tag, map_t *packet_tag_map);
#define str_from_single_packet_tag(packet_tag,packet_tag_map) ((char *(*)(ops_packet_tag_t , packet_tag_map_t *))str_from_map)(packet_tag,packet_tag_map)
char *str_from_map(int ss_type, map_t *ss_type_map);
#define str_from_single_ss_type(ss_type,ss_type_map) ((char *(*)(ops_ss_type_t , ss_type_map_t *))str_from_map)(ss_type,ss_type_map)
