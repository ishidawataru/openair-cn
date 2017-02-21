/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under 
 * the Apache License, Version 2.0  (the "License"); you may not use this file
 * except in compliance with the License.  
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*****************************************************************************

  Source      EmmCommonProcedureInitiated.c

  Version     0.1

  Date        2012/10/03

  Product     NAS stack

  Subsystem   EPS Mobility Management

  Author      Frederic Maurel

  Description Implements the EPS Mobility Management procedures executed
        when the EMM-SAP is in EMM-COMMON-PROCEDURE-INITIATED state.

        In EMM-COMMON-PROCEDURE-INITIATED state, the MME has started
        a common EMM procedure and is waiting for a response from the
        UE.

*****************************************************************************/
#include <pthread.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <assert.h>

#include "bstrlib.h"

#include "log.h"
#include "common_defs.h"
#include "emm_fsm.h"
#include "commonDef.h"
#include "3gpp_24.007.h"
#include "3gpp_24.008.h"
#include "3gpp_29.274.h"
#include "mme_app_ue_context.h"
#include "emm_proc.h"
#include "mme_app_defs.h"


/****************************************************************************/
/****************  E X T E R N A L    D E F I N I T I O N S  ****************/
/****************************************************************************/

/****************************************************************************/
/*******************  L O C A L    D E F I N I T I O N S  *******************/
/****************************************************************************/

/****************************************************************************/
/******************  E X P O R T E D    F U N C T I O N S  ******************/
/****************************************************************************/

/****************************************************************************
 **                                                                        **
 ** Name:    EmmCommonProcedureInitiated()                             **
 **                                                                        **
 ** Description: Handles the behaviour of the MME while the EMM-SAP is in  **
 **      EMM_COMMON_PROCEDURE_INITIATED state.                     **
 **                                                                        **
 **              3GPP TS 24.301, section 5.1.3.4.2                         **
 **                                                                        **
 ** Inputs:  evt:       The received EMM-SAP event                 **
 **      Others:    emm_fsm_status                             **
 **                                                                        **
 ** Outputs:     None                                                      **
 **      Return:    RETURNok, RETURNerror                      **
 **      Others:    emm_fsm_status                             **
 **                                                                        **
 ***************************************************************************/
int
EmmCommonProcedureInitiated (
  const emm_reg_t * evt)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  int                                     rc = RETURNerror;
  emm_context_t                          *emm_ctx = evt->ctx;

  assert (emm_fsm_get_state (emm_ctx) == EMM_COMMON_PROCEDURE_INITIATED);

  switch (evt->primitive) {
  case _EMMREG_COMMON_PROC_ABORT:
    if (evt->u.common.common_proc) {
      if (((nas_base_proc_t*)evt->u.common.common_proc)->parent) {
        rc = nas_unlink_procedures(&((nas_base_proc_t*)evt->u.common.common_proc)->parent, &((nas_base_proc_t*)evt->u.common.common_proc));
      }

      if (evt->u.common.common_proc->emm_proc.base_proc.abort) {
        (*evt->u.common.common_proc->emm_proc.base_proc.abort)(emm_ctx);
      }

      rc = emm_fsm_set_state (evt->ue_id, emm_ctx, ((nas_emm_proc_t*)evt->u.common.common_proc)->previous_emm_fsm_state);

      if ((rc != RETURNerror) && (emm_ctx) && (evt->notify) && (evt->u.common.common_proc->emm_proc.base_proc.failure_notif)) {
        (*evt->u.common.common_proc->emm_proc.base_proc.failure_notif)(emm_ctx);
      }
      nas_free_procedure(emm_ctx, &((nas_base_proc_t*)evt->u.common.common_proc));
    }
    break;

  case EMMREG_ATTACH_ABORT:
    AssertFatal(0, "TODO");
    break;

  case _EMMREG_COMMON_PROC_CNF:

    /*
     * An EMM common procedure successfully completed;
     */

    if (evt->u.common.common_proc) {
      if (((nas_base_proc_t*)evt->u.common.common_proc)->parent) {
        rc = nas_unlink_procedures(&((nas_base_proc_t*)evt->u.common.common_proc)->parent, &((nas_base_proc_t*)evt->u.common.common_proc));
      }

      rc = emm_fsm_set_state (evt->ue_id, emm_ctx, ((nas_emm_proc_t*)evt->u.common.common_proc)->previous_emm_fsm_state);

      if ((rc != RETURNerror) && (emm_ctx) && (evt->notify)) {
        (*evt->u.common.common_proc->emm_proc.base_proc.success_notif)(emm_ctx);
      }
      nas_free_procedure(emm_ctx, &((nas_base_proc_t*)evt->u.common.common_proc));
    }

    break;

  case _EMMREG_COMMON_PROC_REJ:
    /*
     * An EMM common procedure failed;
     * enter state EMM-DEREGISTERED.
     */
    rc = emm_fsm_set_state (evt->ue_id, emm_ctx, EMM_DEREGISTERED);

    if ((rc != RETURNerror) && (emm_ctx) && (evt->notify) && (evt->u.common.common_proc->emm_proc.base_proc.failure_notif)) {
      rc = (*evt->u.common.common_proc->emm_proc.base_proc.failure_notif)(emm_ctx);
    }

    // TODO conditionally, check if parent proc delete childs !!!
    if (evt->free_proc) {
      nas_free_procedure(emm_ctx, &((nas_base_proc_t*)evt->u.common.common_proc));
    }

    break;

  case _EMMREG_ATTACH_CNF:
    /*
     * Attach procedure successful and default EPS bearer
     * context activated;
     * enter state EMM-REGISTERED.
     */
    rc = emm_fsm_set_state (evt->ue_id, emm_ctx, EMM_REGISTERED);
    break;

  case _EMMREG_ATTACH_REJ:
    /*
     * Attach procedure failed;
     * enter state EMM-DEREGISTERED.
     */
    rc = emm_fsm_set_state (evt->ue_id, emm_ctx, EMM_DEREGISTERED);
    nas_free_procedure(emm_ctx, &(nas_base_proc_t*)evt->u.attach.attach_proc);
    break;

  case _EMMREG_LOWERLAYER_SUCCESS:
    /*
     * Data successfully delivered to the network
     */
    rc = RETURNok;
    break;

  case _EMMREG_LOWERLAYER_RELEASE:
  case _EMMREG_LOWERLAYER_FAILURE:
    /*
     * Transmission failure occurred before the EMM common
     * procedure being completed
     */

    if ((rc != RETURNerror) && (emm_ctx) && (evt->notify) && (evt->u.ll_failure.emm_proc.base_proc.failure_notif)) {
      (*evt->u.ll_failure.emm_proc.base_proc.failure_notif)(emm_ctx);
    }

    rc = emm_fsm_set_state (evt->ue_id, emm_ctx, EMM_DEREGISTERED);

    break;

  case _EMMREG_LOWERLAYER_NON_DELIVERY:
    if ((rc != RETURNerror) && (emm_ctx) && (evt->notify) && (evt->u.non_delivery_ho.emm_proc.base_proc.failure_notif)) {
      rc = (*evt->u.non_delivery_ho.emm_proc.base_proc.failure_notif)(emm_ctx);
    } else {
      rc = RETURNok;
    }
    if (rc != RETURNerror) {
      rc = emm_fsm_set_state (evt->ue_id, emm_ctx, EMM_DEREGISTERED);
    }
    break;

  default:
    OAILOG_ERROR (LOG_NAS_EMM, "EMM-FSM   - Primitive is not valid (%d)\n", evt->primitive);
    break;
  }

  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}

/****************************************************************************/
/*********************  L O C A L    F U N C T I O N S  *********************/
/****************************************************************************/
