#include "pe_info.h"
#include <windows.h>
#include <iostream>

using namespace std;

int main(int argc,char* argv[]) {
	if (argc != 2) {
		cout << "Usage: PETool.exe sample.exe" << endl;
		return 0;
	}
	LPTSTR lpFilePath = argv[1];
	PE_info mype;
	if (mype.Is_PE_file(lpFilePath)) {
		cout << "This is PE format" << endl;
		cout << "####################### start analyzing ######################" << endl;
		cout << endl;
		mype.SHOW_DOS_HEADER();
		mype.SHOW_NT_HEADER();
		mype.SHOW_SECTIONS();
		mype.SHOW_IMPORT_DIR_INFO();
		mype.SHOW_EXPORT_DIR_INFO();
	};
	
}