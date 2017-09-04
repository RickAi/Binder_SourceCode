#define LOG_TAG "FregServer"

#include <stdlib.h>
#include <fcntl.h>

#include <utils/Log.h>
#include <binder/IServiceManager.h>
#include <binder/IPCThreadState.h>

#include "../common/IFregService.h"

#define FREG_DEVICE_NAME "/dev/freg"

class FregService : public BnFregService
{
public:
	FregService()
	{
		fd = open(FREG_DEVICE_NAME, O_RDWR);
		if(fd == -1) {
			LOGE("Failed to open device %s.\n", FREG_DEVICE_NAME);
		}
	}

	virtual ~FregService()
	{
		if(fd != -1) {
			close(fd);
		}
	}

public:
	static void instantiate()
	{
		defaultServiceManager()->addService(String16(FREG_SERVICE), new FregService());
	}

	int32_t getVal()
	{
		int32_t val = 0;

		if(fd != -1) {
			read(fd, &val, sizeof(val));
		}

		return val;
	}

	void setVal(int32_t val)
        {
                if(fd != -1) {
                        write(fd, &val, sizeof(val));
                }
        }

private:
	int fd;
};

int main(int argc, char** argv)
{
	FregService::instantiate();

	ProcessState::self()->startThreadPool();
	IPCThreadState::self()->joinThreadPool();

	return 0;
}
