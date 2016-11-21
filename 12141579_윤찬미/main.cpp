#include <Windows.h>
#include <tchar.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>
using namespace std;

wchar_t cmd[] = L"C:\\Users\\assist304\\Desktop\\Fuzzing\\mutate.avi";
const char forg[] = "C:\\Users\\assist304\\Desktop\\Fuzzing\\org.avi";
const char fmut[] = "C:\\Users\\assist304\\Desktop\\Fuzzing\\mutate.avi";

void ChunkSize(char *buf, const size_t bufsize, const size_t mutcount) {

	for (size_t i = 4; i< mutcount; i++)	// 데이터의 크기를 줄인다. 마이너스가 될 수도 있으므로 이것은 fuzzing 날 확률이 높다고 생각했다..!
	{
		buf[i] = buf[i] - '\x01';
	}
}

void MaxPerSec(char *buf, const size_t bufsize, const size_t mutcount) {
	for (size_t i = 0x84; i< mutcount; i++)		// maxpersec 의 모든 비트를 0으로 만들어서 초당 전송 바이트를 없애게 하여 전송 시키지 못하게한다.
	{
		buf[i] = '\x00';
	}
}
void TotalFrame(char *buf, const size_t bufsize, const size_t mutcount) {

	for (size_t i = 0x90; i < mutcount; i++)
	{
		buf[i] = buf[i] / '\x03';	//토탈 프레임의 갯수를 변조시킨다. 
	}
}

int main() {
	cout << "RUN START" << endl;
	ifstream ifs(forg, ios::binary | ios::in);
	ofstream ofs(fmut, ios::binary | ios::out | ios::trunc);
	if (!ifs | !ofs) {
		if (!ifs) cerr << forg << " not found!" << endl;
		if (!ofs) cerr << fmut << " not found!" << endl;
	}
	ifs.seekg(0, ifs.end);
	size_t flen = ifs.tellg();
	ifs.seekg(0);
	const size_t bufsize = 1024;
	char buf[bufsize] = "";
	const size_t chunksizebyte = 0x08;	// chunksize는 0x04부터 4바이트 이므로 0x08까지이다.
	const size_t MPSbyte = 0x88;		// MaxPersecbyte 는 0x80 에서 4바이트의  MicroSecPerFrame 의 뒤에 위치한 4바이트 이다.
	const size_t Total = 0x94;			// 4바이트 크기를 가지는 4개의 파일 정보 후에 위치한 TotalFrame 의 마지막 위치는 0x93 이기에 0x94로 지정
	srand(time(NULL));
	ifs.read(buf, flen % bufsize);	// avi파일의 내용을 읽어 들인다.

									// buf의 값을 바꿔준다.
	ChunkSize(buf, flen%bufsize, chunksizebyte);	// mutate 한다.
	MaxPerSec(buf, flen%bufsize, MPSbyte);	// mutate 한다.
	TotalFrame(buf, flen%bufsize, Total);	// mutate 한다.

	ofs.write(buf, flen%bufsize);

	// mutate한 buf을 mut.avi 파일에 다시 쓴다.
	while (ifs.read(buf, bufsize))
	{
		ChunkSize(buf, flen%bufsize, chunksizebyte);
		MaxPerSec(buf, flen%bufsize, MPSbyte);
		TotalFrame(buf, flen%bufsize, Total);
		ofs.write(buf, flen%bufsize);

	}
	ifs.close();
	ofs.close();


	if ((int)ShellExecute(NULL, TEXT("open"), cmd, NULL, NULL, SW_SHOW) < 32)
		exit(0);
	/* CreateProcess가 에러가 나기 때문에 ShellExecute 를 사용하였다. 32비트 이기 때문에 32보다 작으면 에러가 난다.
	cmd 위치의 파일을 open 한다.

	*/

	return 0;
}