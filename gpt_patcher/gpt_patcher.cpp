// gpt_patcher.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <vector>
#include <Windows.h>
#include "pugixml/pugixml.hpp"

using namespace std;
using namespace pugi;

struct patch_entry 
{
	uint16_t	sector_size;
	uint16_t	byte_offset;
	string		filename;
	uint8_t		part_numb;
	uint8_t		size_in_bytes;
	string		start_sector;
	string		value;
	string		what;
};

vector<string> split(string str, char d)
{
	vector<string> res;
	string w = "";
	for (char s : str)
	{
		if (s == d)
		{
			res.push_back(w);
			w = "";
		}
		else
			w = w + s;
	}
	res.push_back(w);
	return res;
}
pair<string, string> getpair(string str) 
{
	vector<string> sp = split(str, ',');
	pair<string, string> a(sp.at(0), sp.at(1));
	return a;
}
uint64_t parseNumb(string start_sector, uint64_t size, uint16_t sector_size) 
{
	uint64_t result;
	if (start_sector.find("NUM_DISK_SECTORS-") != string::npos)
	{
		string str = start_sector;
		str.erase(0, 17);
		str.erase(str.size() - 1, 1);
		sscanf_s(str.c_str(), "%llu", &result);
		result = (size / sector_size) - result;
	}
	else
	{
		sscanf_s(start_sector.c_str(), "%llu", &result);
	}
	return result;
}
uint32_t crc32(void *data, size_t size)
{
	uint32_t table[256];
	uint32_t crc;
	for (int i = 0; i < 256; i++)
	{
		crc = i;
		for (int j = 0; j < 8; j++)
			crc = crc & 1 ? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;
		table[i] = crc;
	}

	uint32_t instance = ~0U;

	const uint8_t *p = reinterpret_cast<const uint8_t*>(data);
	while (size--)
		instance = table[(instance^*p++) & 0xff] ^ (instance >> 8);

	return instance ^ ~0U;
}

bool read_buff(HANDLE h, void* buff, uint64_t offset, uint64_t len) 
{
	LONG upper = offset >> 32;
	DWORD ret = SetFilePointer(h, offset, &upper, FILE_BEGIN);
	if (ret == INVALID_SET_FILE_POINTER) 
	{
		fprintf(stdout, "Failed to move file pointer.\n");
		return false;
	}
		
	if (!ReadFile(h, buff, len, &ret, 0)) 
	{
		fprintf(stdout, "Failed to read file data.\n");
		return false;
	}
	return true;
}
bool write_buff(HANDLE h, void *buff, uint64_t offset, uint32_t len) 
{
	LONG upper = offset >> 32;
	DWORD ret = SetFilePointer(h, offset, &upper, FILE_BEGIN);
	if (ret == INVALID_SET_FILE_POINTER)
	{
		fprintf(stdout, "Failed to move file pointer.\n");
		return false;
	}

	if (!WriteFile(h, buff, len, &ret, 0)) 
	{
		DWORD err = GetLastError();
		fprintf(stdout, "Failed to read file data.\n");
		return false;
	}
	return true;
}

void help(const char *app) 
{
	vector<string> s = split(app, '\\');
	const char *path = s.at(s.size() - 1).c_str();

	fprintf(stdout, "Usage - %s -i <disk or file> -p <patch_xml_file> [-s <disk_size>]\n"
		"** - disk_size is optional but if you use only in gpt file size must be declared **\n"
		"** - if disk_size is not declared, disk_size is the same as input disk or file size **\n"
		"** - disk_size must be base 16 hex numeric system. (eg. 0x800000, 800000 write as you like) **\n", path);
};

int parse_xml(const char *path, vector<patch_entry> *entries) 
{
	xml_document doc;
	xml_parse_result res = doc.load_file(path);
	if (res.status != status_ok) 
	{
		fprintf(stdout, "Failed to parse patch xml file.\n");
		return -1;
	}
	
	xml_node node = doc.child("patches");
	for (xml_node_iterator it = node.begin(); it != node.end(); ++it) 
	{
		if (strcmp(it->name(), "patch") == 0) 
		{
			patch_entry e = {};
			for (xml_attribute_iterator ait = it->attributes_begin(); ait != it->attributes_end(); ++ait) 
			{
				if (strcmp(ait->name(), "SECTOR_SIZE_IN_BYTES") == 0)
					e.sector_size = ait->as_uint();
				else if (strcmp(ait->name(), "byte_offset") == 0)
					e.byte_offset = ait->as_uint();
				else if (strcmp(ait->name(), "filename") == 0)
					e.filename = ait->as_string();
				else if (strcmp(ait->name(), "physical_partition_number") == 0)
					e.part_numb = ait->as_uint();
				else if (strcmp(ait->name(), "size_in_bytes") == 0)
					e.size_in_bytes = ait->as_uint();
				else if (strcmp(ait->name(), "start_sector") == 0)
					e.start_sector = ait->as_string();
				else if (strcmp(ait->name(), "value") == 0)
					e.value = ait->as_string();
				else if (strcmp(ait->name(), "what") == 0)
					e.what = ait->as_string();
			}
			
			if (strcmp(e.filename.c_str(), "DISK"))
				continue;
			entries->push_back(e);
		}
	}
	
	return 0;
}
int patch_gpt(unsigned long long size, const char *input, vector<patch_entry> entries) 
{
	HANDLE h = CreateFileA(input,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING,
		NULL);

	if (h == INVALID_HANDLE_VALUE) 
	{
		DWORD err = GetLastError();
		fprintf(stdout, "Can't open file or disk\n");
		return -1;
	}

	DISK_GEOMETRY_EX g = { 0 };
	DWORD bret = 0;
	bool ret = DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, 0, 0, &g, sizeof(g), &bret, 0);
	uint64_t filesize = g.DiskSize.QuadPart;
	if (filesize == 0)
	{
		DWORD high = 0, low = 0;
		low = GetFileSize(h, &high);
		filesize = ((size_t)high << 32) | (size_t)low;
	}

	if (size == 0)
		size = filesize;

	if (size < 100 * 10248576) 
	{
		fprintf(stdout, "Invalid disk/file size.\n");
		return -1;
	}

	for (vector<patch_entry>::iterator it = entries.begin(); it != entries.end(); ++it) 
	{
		patch_entry e = *it;
		
		if (size % e.sector_size) 
		{
			fprintf(stdout, "Invalid disk/file size aligned.\n");
			return -1;
		}

		uint64_t start_sector = parseNumb(e.start_sector, size, e.sector_size);
		if (start_sector * e.sector_size > filesize)
			continue;

		fprintf(stdout, "%s...", e.what.c_str());

		uint64_t value = 0;
		{
			if (e.value.find("NUM_DISK_SECTORS-") != string::npos) 
			{
				string str = e.value;
				str.erase(0, 17);
				str.erase(str.size() - 1, 1);
				sscanf_s(str.c_str(), "%llu", &value);
				value = (size / e.sector_size) - value;
			}
			else if (e.value.find("CRC32") != string::npos) 
			{
				string str = e.value;
				str.erase(0, 6);
				str.erase(str.size() - 1, 1);
				pair<string, string > p = getpair(str);
				
				uint64_t crc_offset = parseNumb(p.first, size, e.sector_size) * e.sector_size;
				uint64_t crc_length = 0;
				sscanf_s(p.second.c_str(), "%llu", &crc_length);

				char *buff = (char*)calloc(sizeof(char), crc_length > e.sector_size ? crc_length : e.sector_size);
				if (!read_buff(h, buff, crc_offset, crc_length > e.sector_size? crc_length : e.sector_size))
					return -1;

				value = crc32(buff, crc_length);
				free(buff);
			}
			else 
			{
				sscanf_s(e.value.c_str(), "%llu", &value);
				cout << "wait";
			}
		}

		///patching
		{
			char buff[512];
			uint64_t start_offset = (start_sector * e.sector_size);
			if (!read_buff(h, buff, start_offset, sizeof(buff)))
				return -1;
			memcpy(buff + e.byte_offset, &value, e.size_in_bytes);
			if (!write_buff(h, buff, start_offset, sizeof(buff)))
				return -1;
			fprintf(stdout, "DONE\n");
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 5) 
	{
		fprintf(stdout, "Imcompleted parameters.\n");
		help(argv[0]);
		return 0;
	}

	const char *gpt_file = 0, *patch_file = 0;
	unsigned long long disk_size = 0;

	for (int i = 1; i < argc; i += 2) 
	{
		if (strcmp(argv[i], "-i") == 0)
			gpt_file = argv[i + 1];
		else if (strcmp(argv[i], "-p") == 0)
			patch_file = argv[i + 1];
		else if (strcmp(argv[i], "-s") == 0)
			sscanf_s(argv[i + 1], "%16llx", &disk_size);
	}

	if (!gpt_file) 
	{
		fprintf(stdout, "Invliad gpt file path.\n");
		help(argv[0]);
		return 0;
	}
	if (!patch_file) 
	{
		fprintf(stdout, "Invalid patch xml file path.\n");
		help(argv[0]);
		return 0;
	}

	if (strcmp(gpt_file, "\\\\.\\") != 0 && disk_size == 0) 
	{
		fprintf(stdout, "Patching gpt file must need disk_size value.\n");
		help(argv[0]);
		return 0;
	}
	
	vector<patch_entry> entries;

	int ret = parse_xml(patch_file, &entries);
	if (ret == 0) 
		patch_gpt(disk_size, gpt_file, entries);

	return 0;
}

