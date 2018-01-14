#pragma once
#ifndef _PE_INFO_H
#define _PE_INFO_H
#include <windows.h>

class PE_info
{
public:
	bool Is_PE_file(LPTSTR lpFilePath);//check whether it's a pe file
	void SHOW_DOS_HEADER();
	void SHOW_NT_HEADER();
	void SHOW_SECTIONS();
	void SHOW_IMPORT_DIR_INFO();
	void SHOW_IMPORT_FUNC();
	void SHOW_EXPORT_DIR_INFO();
	void SHOW_EXPORT_FUNC();

private:
	void SHOW_FILE_HEADER();
	void SHOW_OPTIONAL_HEADER();
	void SHOW_DATADIR_INFO();

};



#endif // !_PE_INFO_H
