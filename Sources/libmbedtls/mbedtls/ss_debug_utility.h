//
//  ss_debug_utility.h
//  mbedTLS
//
//  Created by Siddarth Gandhi on 4/6/20.
//  Copyright © 2020 SimpliSafe. All rights reserved.
//

#ifndef ss_debug_utility_h
#define ss_debug_utility_h

#include <stdio.h>

void debug_msg( void *ctx, int level,
               const char *file, int line, const char *str );

#endif /* ss_debug_utility_h */
