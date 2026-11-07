#include <mach-o/dyld.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char **argv){
 (void)argc;
 char own[PATH_MAX],realown[PATH_MAX],target[PATH_MAX],realtarget[PATH_MAX]; uint32_t n=sizeof own;
 if(_NSGetExecutablePath(own,&n)||!realpath(own,realown))return 126;
 char *s=strrchr(own,'/'); if(!s)return 126; *s=0;
 if(strlen(own)+40>=sizeof own)return 126;
 strcat(own,"/../Resources/original-executable");
 FILE*f=fopen(own,"r");if(!f)return 126;
 if(!fgets(target,sizeof target,f)){fclose(f);return 126;}fclose(f);
 target[strcspn(target,"\r\n")]=0;
 if(target[0]!='/'||!realpath(target,realtarget)||!strcmp(realown,realtarget))return 126;
 argv[0]=target;execv(target,argv);return 127;
}
