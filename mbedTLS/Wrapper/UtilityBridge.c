//
//  UtilityBridge.c
//  mbedTLS
//
//  Created by Siddarth Gandhi on 2/26/19.
//  Copyright © 2019 SimpliSafe. All rights reserved.
//

#include "UtilityBridge.h"

void debug_msg( void *ctx, int level,
               const char *file, int line, const char *str )
{
    ((void) level);
    fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}
