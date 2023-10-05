#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>


#include <cpuinfo.h>
#include <cpuinfo/log.h>
#include <powerpc/api.h>
#include <powerpc/linux/api.h>
#include <linux/api.h>

#define NUM_CACHE   4
#define BUF_SIZE    128

int path_exist(const char *path){
	return (access(path, F_OK) == 0);
}

#define	BUFFER_SIZE 128

/* Locale-independent */
inline static const bool is_whitespace(char c) {
	switch (c) {
		case ' ':
		case '\t':
		case '\n':
		case '\r':
			return true;
		default:
			return false;
	}
}

inline static const char* parse_number(const char* start, const char* end, uint32_t number_ptr[restrict static 1]) {
	uint32_t number = 0;
	const char* parsed = start;
	for (; parsed < end; parsed++) {
		const uint32_t digit = (uint32_t) (uint8_t) (*parsed) - (uint32_t) '0';
		if (digit >= 10) {
			break;
		}
		number = number * UINT32_C(10) + digit;
	}
	*number_ptr = number;
	return parsed;
}

inline static const size_t read_line_from_file(char *result, size_t len, const char *path){
	FILE* file = fopen(path, "r");
	if (file == NULL){
		cpuinfo_log_error("could not open file: %s", path);
		exit(-1);
	}

	if ( fgets(result, len, file) == NULL ){
		cpuinfo_log_error("failed read line from file '%s'", path);
		exit(-1);
	}
	fclose(file);

	len = strlen(result)-1;
	if (result[len] == '\n'){
		result[len] = '\0';
	}
	return len;
}

inline static const uint32_t readOrDefault(const char *path, uint32_t defaultVal ){
	if(path_exist(path)) {
		char readbuf[BUF_SIZE];
		read_line_from_file(readbuf, sizeof(readbuf), path);
		return atoi(readbuf);
	} else{
		return defaultVal;
	}
}

inline static bool assignOrNull(struct cpuinfo_cache cacheLevel[restrict static 1], struct cpuinfo_cache cacheInfo[restrict static 1]) {
	if (cacheInfo->size!=0){
		*cacheLevel = *cacheInfo;
		return true;
	} else {
		cacheLevel = NULL;
		return false;
		// cpuinfo_log_debug("cache assign NULL");
	}
}

inline static const bool parse_list(const char* text_start, const char* text_end, struct List* list_out){
    if (text_start == text_end) {
        cpuinfo_log_error("failed to parse file: file is empty");
        exit(-1);
    }

	// default initialize for one element
	struct List list = {  };

    // check for separators
	const char* comma_ptr = strchr( text_start, ',' );
	const char* dash_ptr = strchr( text_start, '-' );

    if (comma_ptr != NULL && dash_ptr != NULL){ // both found must be mixed format
        // sequential read
		cpuinfo_log_error("parse_topology_file: parse_list: format not implemented!");
		exit(-1);
    }
	else if (comma_ptr != NULL){ // only comma found: must be x,y,z format
		list.isRange=false;
		list.size = 0;
		// SMT4 may use 4  entires
		uint32_t capacity = 4;
		list.ptr = (uint32_t*) malloc (capacity*sizeof(uint32_t));

		const char* start = text_start;
		char* parsed;
		while ((parsed = parse_number(start, text_end, &list.ptr[list.size])) > start){
			list.size++;
			start = parsed;
			start++;
			// cpuinfo_log_debug("parse_list: %s", start);

			// check and resize
			if (list.size==capacity){
				capacity *= 2;
				void* newMem = realloc(list.ptr, capacity*sizeof(uint32_t));
				if (!newMem){
					cpuinfo_log_error("failed to allocate memory!");
					free(list.ptr);
					exit(-1);
				}
				list.ptr = (uint32_t*) newMem;
			}
		}
    }
    else if (dash_ptr != NULL){ // only dash found: must be x-y format
		list.isRange = true;
		list.size = 2;
		list.ptr = (uint32_t*) malloc (list.size*sizeof(uint32_t));

        parse_number(text_start, dash_ptr, &list.ptr[0]);
        parse_number(dash_ptr+1, text_end, &list.ptr[1]);
    }
	else { // no valid separator found, must be a single number
		list.isRange = false;
		list.size = 1;
		list.ptr = (uint32_t*) malloc (list.size*sizeof(uint32_t));

        parse_number(text_start, text_end, &list.ptr[0]);
    }

	*list_out = list;
	return true;
}

const bool parse_topology_file(const char* filename, struct List* list){
	if(!path_exist(filename)) {
		cpuinfo_log_debug("parse_topology_file: file not found '%s'", filename);
		return false;
	}

	char line[BUFFER_SIZE];
	const size_t chars_read = read_line_from_file(line, sizeof(line), filename);

	if (parse_list(line, &line[chars_read], list)){
		return true;
	} else {
		return false;
	}
}

const bool cpuinfo_powerpc_decode_cache(
	uint32_t smt_id,
	uint32_t level_id,
	struct cpuinfo_cache cache[restrict static 1]
)
{
	char buf[BUF_SIZE];
	char result[BUF_SIZE];
	uint32_t size = 0, associativity = 0, line_size = 0, sets = 0, partitions = 1;
	size_t len;

	struct cpuinfo_cache cacheInfo = (struct cpuinfo_cache) {
		.size = 0,
		.associativity = 0,
		.line_size = 0,
		.sets = 0,
		.partitions = 1
	};

	sprintf (buf, "/sys/devices/system/cpu/cpu%d/cache/index%d/size", smt_id, level_id);
	if(path_exist(buf)) {
		read_line_from_file(result, sizeof(result), buf);
		len = strlen(result);
		if (result[len - 1] == 'K')
			result[len - 1] = '\0';
		cacheInfo.size = 1024 * atoi(result);
	}else{
		cacheInfo.size = 0;
	}

	// sets and associativity are switched in linux kernel 4.18
	// sprintf (buf, "/sys/devices/system/cpu/cpu%d/cache/index%d/ways_of_associativity", smt_id, level_id);
	sprintf (buf, "/sys/devices/system/cpu/cpu%d/cache/index%d/number_of_sets", smt_id, level_id);
	cacheInfo.associativity = readOrDefault(buf, 0);

	// sprintf (buf, "/sys/devices/system/cpu/cpu%d/cache/index%d/number_of_sets", smt_id, level_id);
	sprintf (buf, "/sys/devices/system/cpu/cpu%d/cache/index%d/ways_of_associativity", smt_id, level_id);
	cacheInfo.sets = readOrDefault(buf, 0);

	sprintf (buf, "/sys/devices/system/cpu/cpu%d/cache/index%d/coherency_line_size", smt_id, level_id);
	cacheInfo.line_size = readOrDefault(buf, 0);

	if ( (cacheInfo.size) != (cacheInfo.associativity * cacheInfo.sets * cacheInfo.partitions * cacheInfo.line_size) ){
		cpuinfo_log_error(
			"cache level %"PRIu32": size %"PRIu32" != associativity %"PRIu32" * sets %"PRIu32" * partitions %"PRIu32" * line_size %"PRIu32"",
			level_id, cacheInfo.size, cacheInfo.associativity, cacheInfo.sets, cacheInfo.partitions, cacheInfo.line_size);
		exit(-1);
	}

	return assignOrNull(cache, &cacheInfo);
}