char *str_from_map(int packet_tag, map_t *packet_tag_map);
#define show_packet_tag(packet_tag,packet_tag_map) ((char *(*)(ops_packet_tag_t , packet_tag_map_t *))str_from_map)(packet_tag,packet_tag_map)
char *str_from_map(int sig_type, map_t *sig_type_map);
#define show_sig_type(sig_type,sig_type_map) ((char *(*)(ops_sig_type_t , sig_type_map_t *))str_from_map)(sig_type,sig_type_map)
char *str_from_map(int pka, map_t *pka_map);
#define show_pka(pka,pka_map) ((char *(*)(ops_public_key_algorithm_t , public_key_algorithm_map_t *))str_from_map)(pka,pka_map)
char *str_from_map(int ss_type, map_t *ss_type_map);
#define show_ss_type(ss_type,ss_type_map) ((char *(*)(ops_ss_type_t , ss_type_map_t *))str_from_map)(ss_type,ss_type_map)
char *str_from_map(int ss_rr_code, map_t *ss_rr_code_map);
#define show_ss_rr_code(ss_rr_code,ss_rr_code_map) ((char *(*)(ops_ss_rr_code_t , ss_rr_code_map_t *))str_from_map)(ss_rr_code,ss_rr_code_map)
