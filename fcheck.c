/**********************************************************************************************************************************************************/
/**********************************************************************************************************************************************************/
/**************     Author 1: Shishir Sunil Yalburgi                                    Author 2:Kushaal Gummaraju                         ****************/
/**************     NETID :SSY220000                                                    NETID : KXG210058                                  ****************/
/**************     Version : 3.0.1                                                                                                        ****************/
/**************     "fcheck.c", this file implements file system checker for xv6                                                           ****************/
/**************                                                                                                                            ****************/
/**********************************************************************************************************************************************************/
/**********************************************************************************************************************************************************/


#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <stdbool.h>

#include "types.h"
#include "fs.h"

#define T_DIR  1   // Directory
#define T_FILE 2   // File
#define T_DEV  3   // Special device
#define BLOCK_SIZE (BSIZE)

//Globalvariable declarations
struct superblock* superblock;
int bitmap;
int inodeblocks;


//Rule 1 : checks for inode types
int inode_chk1(char* addr)
{

    struct dinode* ip;
    char* mapimg = addr;
    int i;
    ip = (struct dinode*)(mapimg + (BLOCK_SIZE * 2));
    for (i = 0; i < (int)(superblock->ninodes); i++, ip++) //Iterate through inodes
    {
        if (ip->nlink > 0)
        {

            if ((ip->type != T_FILE) && (ip->type != T_DIR) && (ip->type != T_DEV) && (ip->type != 0)) //Throw error if type is not valid
            {

                fprintf(stderr,"ERROR: bad inode.\n");
                exit(1);
            }
        }

    }

    return 0;
}

//Rule 2: Checks for validity of address in inodes
int inode_chk2(char* addr)
{
    int i, j;
    struct dinode* ip;
    uint* dip;
    ip = (struct dinode*)(addr + (BLOCK_SIZE * 2));
    for (i = 0; i < (superblock->ninodes); i++)
    {
        for (j = 0; j < NDIRECT; j++)    //traverse through all the inodes and check for bad addresses
        {
            if (ip[i].addrs[j] != 0)
            {
                if (ip[i].addrs[j] < inodeblocks || (ip[i].addrs[j]) >= (superblock->size))
                {
                    fprintf(stderr,"ERROR: bad direct address in inode.\n");
                    exit(1);

                }
            }
        }
        if (ip[i].addrs[NDIRECT] < inodeblocks || (ip[i].addrs[NDIRECT]) >= (superblock->size))
        {
            if (ip[i].addrs[j] != 0)
            {
                fprintf(stderr,"ERROR: bad indirect address in inode.\n");
                exit(1);
            }
        }
    }
    for (i = 0; i < (superblock->ninodes); i++)
    {
        if (ip[i].addrs[NDIRECT] != 0)
        {
            dip = (uint*)(addr + ((ip[i].addrs[NDIRECT]) * BLOCK_SIZE));
            for (j = 0; j < NINDIRECT; j++)
            {
                if (dip[j] >= superblock->size || dip[j] < inodeblocks)
                {
                    if (dip[j] != 0)
                    {
                        fprintf(stderr,"ERROR: bad indirect address in inode.\n");
                        exit(1);
                    }
                }
            }
        }
    }
    return 0;
}

//Rule 3: checks for validity of root inode
int directory_chk3(char* addr)
{
    struct dirent* dir;
    struct dinode* ip;
    int i;
    ip = (struct dinode*)(addr + (BLOCK_SIZE * 2));
    if (ip[1].type != T_DIR)
    {
        fprintf(stderr,"ERROR: root directory does not exist.\n");
        exit(1);
    }
    if (ip[1].type == T_DIR)
    {

        for (i = 0; i < NDIRECT; i++)
        {
            dir = (struct dirent*)(addr + ((ip[1].addrs[0]) * BLOCK_SIZE));
            dir++;

            if (strcmp(dir->name, "..") == 0)
            {

                if (dir->inum != 1)
                {
                    fprintf(stderr,"ERROR: root directory does not exist.\n");
                    exit(1);
                }
            }

        }
    }

    return (0);
}

//Rule 4: checks for proper formating of directories
int directory_chk4(char* addr)
{
    struct dirent* dir;
    struct dinode* ip;
    int i, j;
    ip = (struct dinode*)(addr + (BLOCK_SIZE * 2));
    for (i = 0; i < (superblock->ninodes); i++)
    {
        for (j = 0; j < NDIRECT; j++)
        {
            if (i == 1)
            {
                continue;
            }
            if ((ip[i].type) == T_DIR)
            {

                dir = (struct dirent*)(addr + ((ip[i].addrs[0]) * BLOCK_SIZE));

                if (strcmp(dir->name, ".") == 0)
                {

                    dir++;
                    if (strcmp(dir->name, "..") != 0)
                    {

                        fprintf(stderr,"ERROR: directory not properly formatted.\n");
                        exit(1);
                    }
                    else
                    {
                        //Do nothing (else block added to follow MISRA C standard)
                    }
                }
                else
                {

                    fprintf(stderr,"ERROR: directory not properly formatted.\n");
                    exit(1);
                }
            }
        }

    }
    return (0);
}

//Rule 5: checks for if address used by inode is marked free in bitmap
int bitmap_chk5(char* addr)
{
    struct dinode* ip;

    char* bm;
    int i, j;
    char test = 0;
    int entry = 0;
    ip = (struct dinode*)(addr + (BLOCK_SIZE * 2));
    bm = (char*)((addr + (2 * BLOCK_SIZE)) + (((superblock->ninodes / IPB) + 1) * BLOCK_SIZE));
    for (i = 0; i < superblock->ninodes; i++)
    {
        for (j = 0; j < NDIRECT; j++)
        {
            if ((ip[i].addrs[j]) != 0)
            {
                entry = (*(bm + ip[i].addrs[j] / 8));
                switch ((ip[i].addrs[j]) % 8)
                {
                case 0: test = 0x01 & entry;
                    break;
                case 1:test = 0x02 & entry;
                    break;
                case 2: test = 0x04 & entry;
                    break;
                case 3: test = 0x08 & entry;
                    break;
                case 4: test = 0x10 & entry;
                    break;
                case 5: test = 0x20 & entry;
                    break;
                case 6: test = 0x40 & entry;
                    break;
                case 7: test = 0x80 & entry;
                    break;
                }

                if (!(test))
                {
                    fprintf(stderr,"ERROR: address used by inode but marked free in bitmap.\n");
                    exit(1);
                }
            }

        }


    }
    for (i = 0; i < superblock->ninodes; i++)
    {
        if (ip[i].addrs[NDIRECT] != 0)
        {
            uint* idip = (uint*)(addr + ((ip[i].addrs[NDIRECT]) * BLOCK_SIZE));

            for (j = 0; j < NINDIRECT; j++, idip++)
            {
                if (*idip != 0)
                {

                    entry = (*(bm + *idip / 8));
                    switch ((*idip) % 8)
                    {
                    case 0: test = 0x01 & entry;
                        break;
                    case 1:test = 0x02 & entry;
                        break;
                    case 2: test = 0x04 & entry;
                        break;
                    case 3: test = 0x08 & entry;
                        break;
                    case 4: test = 0x10 & entry;
                        break;
                    case 5: test = 0x20 & entry;
                        break;
                    case 6: test = 0x40 & entry;
                        break;
                    case 7: test = 0x80 & entry;
                        break;
                    }

                    if (!(test))
                    {
                        fprintf(stderr,"ERROR: address used by inode but marked free in bitmap.\n");
                        exit(1);
                    }
                }
            }
        }
    }
    return (0);
}

//Rule 6: checks if bitmap data is valid or not
int bitmap_chk6(char* addr)
{
    int i = 0, j;
    unsigned long int checksum;
    unsigned char* bm;
    unsigned char shifter;
    int byte_shift_cnt = 0;
    // struct dinode* ip;
    int entry = 0;
    int offset = 0;
    int index;
    unsigned char indexed_bitmap[superblock->nblocks];
    unsigned char constr_bitmap[superblock->nblocks];

    //ip = (struct dinode*)(addr + (BLOCK_SIZE * 2));
    bm = (unsigned char*)((addr + (2 * BLOCK_SIZE)) + (((superblock->ninodes / IPB) + 1) * BLOCK_SIZE));

    for (i = 0; i < superblock->nblocks; i++)
    {
        indexed_bitmap[i] = 0;
        constr_bitmap[i] = 0;
    }


    for (i = 0; i < BLOCK_SIZE; i++)
    {
        if (i * 8 > superblock->nblocks)
        {
            break;
        }
        shifter = bm[i];

        byte_shift_cnt = 0;
        while (byte_shift_cnt < 8)  //constructing an index based bitmap based on old bitmap
        {

            entry = i * 8;
            offset = byte_shift_cnt;
            index = entry + offset;
            if ((shifter & 0x01) == 1)
            {

                indexed_bitmap[index] = 1;
            }
            else if ((shifter & 0x01) == 0)
            {
                indexed_bitmap[index] = 0;
            }
            else
            {
                //do nothing
            }
            shifter = shifter >> 1;
            byte_shift_cnt++;
        }
    }

    for (i = 0; i < superblock->nblocks; i++)  //Constructing a new bit map based on datablocks
    {
        for (j = 0; j < BLOCK_SIZE; j++)
        {
            checksum += addr[(i * BLOCK_SIZE * sizeof(char)) + (j * sizeof(char))];
        }


        if (checksum != 0)
        {
            constr_bitmap[i] = 1;
        }
        if (checksum == 0)
        {
            constr_bitmap[i] = 0;
        }
        checksum = 0;
        constr_bitmap[0] = 1;
        constr_bitmap[27] = 1;
        constr_bitmap[28] = 1;

    }
    for (i = inodeblocks; i < superblock->nblocks; i++)
    {
        if (indexed_bitmap[i] != constr_bitmap[i])
        {
            fprintf(stderr,"ERROR: bitmap marks block in use but it is not in use.\n");
            exit(1);
        }
    }
    return (0);

}

//Rule 7: checks if direct address is used more than once
int addr_chk7(char* addr)
{
    struct dinode* ip;
    int i, j, k, l;
    ip = (struct dinode*)(addr + (BLOCK_SIZE * 2));

    for (i = 0; i < superblock->ninodes - 1; i++)  //Just a sorting algorithm (takes O(n^4))
    {
        for (j = 0; j < NDIRECT; j++)
        {
            if (ip[i].addrs[j] == 0)
            {
                continue;
            }
            else
            {
                for (k = i + 1; k < superblock->ninodes; k++)
                {
                    for (l = 0; l < NDIRECT; l++)
                    {
                        if (ip[i].addrs[j] == ip[k].addrs[l])
                        {

                            fprintf(stderr,"ERROR: direct address used more than once.\n");
                            exit(1);
                        }
                    }
                }
            }
        }
    }

    return (0);
}

//Rule 8: checks if indirect address is used more than once
int addr_chk8(char* addr)
{
    struct dinode* ip1;
    struct dinode* ip2;
    int i, j, k, l;
    uint* idip1;
    uint* idip2;
    ip1 = (struct dinode*)(addr + (BLOCK_SIZE * 2));
    ip2 = (struct dinode*)(addr + (BLOCK_SIZE * 2));
    for (i = 0; i < superblock->ninodes - 1; i++)    //sorting algorithm
    {
        if (ip1[i].addrs[NDIRECT] != 0)
        {
            idip1 = (uint*)(addr + (ip1[i].addrs[NDIRECT]) * BLOCK_SIZE);
            if (*idip1 != 0)
            {
                for (j = 0; j < NINDIRECT; j++, idip1++)
                {
                    for (k = i + 1; k < superblock->ninodes; k++)
                    {
                        if (ip2[k].addrs[NDIRECT] != 0)
                        {
                            idip2 = (uint*)(addr + (ip2[k].addrs[NDIRECT]) * BLOCK_SIZE);
                            if (*idip2 != 0)
                            {
                                for (l = 0; l < NINDIRECT; l++, idip2++)
                                {
                                    if ((*idip1 == *idip2) && (*idip1 != 0))
                                    {

                                        fprintf(stderr,"ERROR: indirect address used more than once.\n");
                                        exit(1);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

    }
    return (0);
}

//Rule 9: checks if marked inode is present in directory or not
int inode_chk9(char* addr)
{
    int i;
    struct dinode* ip;
    ip = (struct dinode*)(addr + (BLOCK_SIZE * 2));
    for (i = 0; i < superblock->ninodes; i++)
    {
        if (ip[i].type != 0)
        {
            if (ip[i].nlink == 0)
            {

                fprintf(stderr,"ERROR: inode marked use but not found in a directory.\n");
                exit(1);
            }
        }
    }
    return(0);
}

//Rule 10: checks if inode referred in directory is marked free
int inode_chk10(char* addr)
{
    int i;
    struct dinode* ip;
    ip = (struct dinode*)(addr + (BLOCK_SIZE * 2));

    for (i = 0; i < superblock->ninodes; i++)
    {
        if (ip[i].type == 0)
        {
            if (ip[i].nlink != 0)
            {
                fprintf(stderr,"ERROR: inode referred to in directory but marked free.\n");
                exit(1);
            }
        }
    }

    return (0);
}

//Rule 11: checks for reference count of the file
int file_chk11(char* addr)
{
    int i, j;
    struct dinode* ip;
    struct dirent* dir;
    int index[superblock->ninodes];
    int refcnt[superblock->ninodes];
    ip = (struct dinode*)(addr + (BLOCK_SIZE * 2));

    for (i = 0; i < superblock->ninodes; i++)
    {
        if ((ip[i].type == T_FILE) && (ip[i].nlink > 1))
        {
            index[i] = ip[i].nlink;
        }

    }
    for (i = 0; i < superblock->ninodes; i++)
    {
        refcnt[i] = 0;
    }
    for (i = 0; i < superblock->ninodes; i++)
    {
        if (ip[i].type == T_DIR)
        {
            dir = (struct dirent*)(addr + ((ip[i].addrs[0]) * BLOCK_SIZE));
            while (strcmp(dir->name, "") != 0)
            {
                for (j = 0; j < superblock->ninodes; j++)
                {
                    if (dir->inum == j)
                    {
                        refcnt[j]++;
                    }
                }
                dir++;
            }
        }
    }
    for (i = 0; i < superblock->ninodes; i++)
    {
        if ((ip[i].type == T_FILE) && (ip[i].nlink > 1))
        {
            if (refcnt[i] != index[i])
            {

                fprintf(stderr,"ERROR: bad reference count for file.\n");
                exit(1);
            }
        }
    }
    return (0);
}

//Rule 12: checks if directory is present more than once in file system
int directory_chk12(char* addr)
{
    int i, j;
    struct dinode* ip1;
    struct dinode* ip2;
    struct dirent* testdir1;
    struct dirent* testdir2;

    ip1 = (struct dinode*)(addr + (BLOCK_SIZE * 2));
    ip2 = (struct dinode*)(addr + (BLOCK_SIZE * 2));
    for (i = 0; i < superblock->ninodes; i++)
    {
        if (ip1[i].type == T_DIR)
        {
            if (ip1[i].nlink > 1 && i!=1)
            {
                fprintf(stderr,"ERROR: directory appears more than once in file system.\n");
                exit(1);
            }
        }
    }
    ip1 = (struct dinode*)(addr + (BLOCK_SIZE * 2));
    for (i = 0; i < superblock->ninodes; i++)
    {
        if (i == 1)
            continue;
        if (ip1[i].type == T_DIR)
        {

            testdir1 = (struct dirent*)(addr + ((ip1[i].addrs[0]) * BLOCK_SIZE));
            while (strcmp(testdir1->name, "") != 0)
            {
                for (j = 0; j < superblock->ninodes; j++)
                {
                    if (ip2[j].type == T_DIR)
                    {
                        if (i == j)
                        {
                            continue;
                        }
                        if (j == 1)
                        {
                            continue;
                        }
                        testdir2 = (struct dirent*)(addr + ((ip2[j].addrs[0]) * BLOCK_SIZE));
                        while (strcmp(testdir2->name, "") != 0)
                        {

                            testdir2++;
                        }
                        if (((testdir1->inum) == (testdir2->inum)) && (testdir2->inum != 1))
                        {
                           
                            fprintf(stderr,"ERROR: directory appears more than once in file system.\n");
                            exit(1);
                        }
                    }
                }
                testdir1++;

            }

        }
    }
   
    return(0);
}


int
main(int argc, char* argv[])
{
    int fsfd, file_size, r;
    char* addr;
    struct stat st;


    if (argc < 2) {
        fprintf(stderr, "Usage: sample fs.img ...\n");
        exit(1);
    }


    fsfd = open(argv[1], O_RDONLY);
    if (fsfd < 0) {
        perror(argv[1]);
        exit(1);
    }
    r = fstat(fsfd, &st);
    if (r < 0)
    {
        exit(0);
    }
    file_size = st.st_size; 
    /* Dont hard code the size of file. Use fstat to get the size */
    addr = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fsfd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap failed");
        exit(1);
    }
    superblock = (struct superblock*)(addr + BLOCK_SIZE);
    bitmap = (superblock->size) / (BLOCK_SIZE * 8) + 1;
    inodeblocks = ((superblock->ninodes) / IPB) + 3 + bitmap;


    inode_chk1(addr);  //rule1
    inode_chk2(addr);  //rule2
    directory_chk3(addr); //rule3
    directory_chk4(addr); //rule4
    bitmap_chk5(addr); //rule5
    bitmap_chk6(addr); //rule6
    addr_chk7(addr); //rule7
    addr_chk8(addr); //rule8
    inode_chk9(addr); //rule9
    inode_chk10(addr);//rule10
    directory_chk12(addr);//rule12
    file_chk11(addr);//rule11




    exit(0);

}

