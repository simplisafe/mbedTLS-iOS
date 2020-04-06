//
//  ss_debug_utility.c
//  mbedTLS
//
//  Created by Siddarth Gandhi on 4/6/20.
//  Copyright © 2020 SimpliSafe. All rights reserved.
//

#include "mbedtls/ss_debug_utility.h"

void debug_msg( void *ctx, int level,
               const char *file, int line, const char *str )
{
    ((void) level);
    fprintf( (FILE *) ctx, "%04d: %s", line, str );
    fflush(  (FILE *) ctx  );
}
