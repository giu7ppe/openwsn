#ifndef __SCTIMER_H
#define __SCTIMER_H

/**
\addtogroup BSP
\{
\addtogroup sctimer
\{

\brief A timer module with only a single compare value. Can be used to replace
       the "bsp_timer" and "radiotimer" modules with the help of abstimer.

\author Xavi Vilajosana <xvilajosana@eecs.berkeley.edu>, May 2012.
\author Thomas Watteyne <watteyne@eecs.berkeley.edu>, May 2012.
*/

#include "stdint.h"
#include "board.h"

//=========================== define ==========================================
#define SCTIMER_TICS_MS 33
//=========================== typedef =========================================

typedef kick_scheduler_t (*sctimer_cbt)();

//=========================== variables =======================================


//=========================== prototypes ======================================

void sctimer_init();
void sctimer_stop();
void sctimer_schedule(PORT_TIMER_WIDTH val);
PORT_TIMER_WIDTH sctimer_getValue();
void sctimer_setCb(sctimer_cbt cb);
void sctimer_clearISR();
void sctimer_reset();

/**
\}
\}
*/

#endif
