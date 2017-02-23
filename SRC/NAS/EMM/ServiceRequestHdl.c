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
  Source      ServiceRequest.c

  Version     0.1

  Date        2013/05/07

  Product     NAS stack

  Subsystem   EPS Mobility Management

  Author      Frederic Maurel

  Description Defines the service request EMM procedure executed by the
        Non-Access Stratum.

        The purpose of the service request procedure is to transfer
        the EMM mode from EMM-IDLE to EMM-CONNECTED mode and establish
        the radio and S1 bearers when uplink user data or signalling
        is to be sent.

        This procedure is used when the network has downlink signalling
        pending, the UE has uplink signalling pending, the UE or the
        network has user data pending and the UE is in EMM-IDLE mode.

*****************************************************************************/
#include <pthread.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "bstrlib.h"

#include "log.h"
#include "msc.h"
#include "dynamic_memory_check.h"
#include "common_types.h"
#include "common_defs.h"
#include "3gpp_24.007.h"
#include "3gpp_24.008.h"
#include "3gpp_29.274.h"
#include "mme_app_ue_context.h"
#include "emm_proc.h"
#include "nas_timer.h"
#include "emm_data.h"
#include "emm_sap.h"
#include "emm_cause.h"
#include "mme_app_defs.h"

/****************************************************************************/
/****************  E X T E R N A L    D E F I N I T I O N S  ****************/
/****************************************************************************/

/****************************************************************************/
/*******************  L O C A L    D E F I N I T I O N S  *******************/
/****************************************************************************/
static int _emm_service_reject (emm_context_t *emm_context, struct nas_base_proc_s * base_proc);
/*
   --------------------------------------------------------------------------
    Internal data handled by the service request procedure in the UE
   --------------------------------------------------------------------------
*/

/*
   --------------------------------------------------------------------------
    Internal data handled by the service request procedure in the MME
   --------------------------------------------------------------------------
*/


/****************************************************************************/
/******************  E X P O R T E D    F U N C T I O N S  ******************/
/****************************************************************************/

int
emm_proc_service_reject (
  mme_ue_s1ap_id_t ue_id,
  enb_ue_s1ap_id_t enb_ue_s1ap_id,
  emm_cause_t emm_cause)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  int                                     rc = RETURNerror;

  /*
   * Create temporary UE context
   */
  struct ue_mm_context_s                     * ue_mm_context = NULL;
  nas_sr_proc_t                              * sr_proc = NULL;

  if (INVALID_MME_UE_S1AP_ID == ue_id) {
    ue_mm_context = mme_ue_context_exists_enb_ue_s1ap_id (&mme_app_desc.mme_ue_contexts, enb_ue_s1ap_id);
    if (ue_mm_context) {
      ue_mm_context->mme_ue_s1ap_id = emm_ctx_get_new_ue_id(&ue_mm_context->emm_context);
      mme_api_notified_new_ue_s1ap_id_association (ue_mm_context->enb_ue_s1ap_id, ue_mm_context->e_utran_cgi.cell_identity.enb_id, ue_mm_context->mme_ue_s1ap_id);
      nas_sr_proc_t * sr_proc = get_nas_con_mngt_procedure_service_request(&ue_mm_context->emm_context);
      if (!sr_proc) {
        sr_proc = nas_new_service_request_procedure(&ue_mm_context->emm_context);
      }
      if (sr_proc) {
        sr_proc->emm_cause = EMM_CAUSE_IMPLICITLY_DETACHED;
      }
    } else {
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
    }
  } else {

    ue_mm_context = mme_ue_context_exists_enb_ue_s1ap_id (&mme_app_desc.mme_ue_contexts, ue_id);
    if (ue_mm_context) {
      nas_sr_proc_t * sr_proc = get_nas_con_mngt_procedure_service_request(&ue_mm_context->emm_context);
      if (!sr_proc) {
        sr_proc = nas_new_service_request_procedure(&ue_mm_context->emm_context);
      }
      if (sr_proc) {
        sr_proc->emm_cause = emm_cause;
      }
    } else {
      OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
    }
  }
  sr_proc->ue_id                                          = ue_id;
  ((nas_base_proc_t *)sr_proc)->parent                    = (nas_base_proc_t*)NULL;
  sr_proc->con_mngt_proc.emm_proc.delivered               = NULL;
  sr_proc->con_mngt_proc.emm_proc.previous_emm_fsm_state  = ue_mm_context->emm_context._emm_fsm_state;
  sr_proc->con_mngt_proc.emm_proc.not_delivered           = NULL;
  sr_proc->con_mngt_proc.emm_proc.not_delivered_ho        = NULL;
  sr_proc->con_mngt_proc.emm_proc.base_proc.success_notif = NULL;
  sr_proc->con_mngt_proc.emm_proc.base_proc.failure_notif = NULL;
  sr_proc->con_mngt_proc.emm_proc.base_proc.abort         = NULL;
  sr_proc->con_mngt_proc.emm_proc.base_proc.fail_in       = NULL; // only response
  sr_proc->con_mngt_proc.emm_proc.base_proc.fail_out      = _emm_service_reject;
  sr_proc->con_mngt_proc.emm_proc.base_proc.time_out      = NULL;

  emm_sap_t                               emm_sap = {0};
  emm_sap.primitive = EMMREG_SERVICE_REJ;
  emm_sap.u.emm_reg.ue_id     = ue_id;
  emm_sap.u.emm_reg.ctx       = &ue_mm_context->emm_context;
  emm_sap.u.emm_reg.notify    = true;
  emm_sap.u.emm_reg.free_proc = true;
  emm_sap.u.emm_reg.u.sr.proc = sr_proc;
  rc = emm_sap_send (&emm_sap);

  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}
/****************************************************************************/
/*********************  L O C A L    F U N C T I O N S  *********************/
/****************************************************************************/

static int _emm_service_reject (emm_context_t *emm_context, struct nas_base_proc_s * base_proc)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);

  int                                     rc = RETURNerror;

  if ((base_proc) && (emm_context)) {
    emm_sap_t                               emm_sap = {0};
    mme_ue_s1ap_id_t                        ue_id = PARENT_STRUCT(emm_context, struct ue_mm_context_s, emm_context)->mme_ue_s1ap_id;
    nas_sr_proc_t                         * sr_proc = (nas_sr_proc_t *)base_proc;

    OAILOG_WARNING (LOG_NAS_EMM, "EMM-PROC  - EMM service procedure not accepted " "by the network (ue_id=" MME_UE_S1AP_ID_FMT ", cause=%d)\n",
        ue_id, sr_proc->emm_cause);


    /*
     * Notify EMM-AS SAP that Tracking Area Update Reject message has to be sent
     * onto the network
     */
    emm_sap.primitive = EMMAS_ESTABLISH_REJ;
    emm_sap.u.emm_as.u.establish.ue_id = ue_id;
    emm_sap.u.emm_as.u.establish.eps_id.guti = NULL;

    if (sr_proc->emm_cause == EMM_CAUSE_SUCCESS) {
      sr_proc->emm_cause = EMM_CAUSE_IMPLICITLY_DETACHED;
    }

    emm_sap.u.emm_as.u.establish.emm_cause = sr_proc->emm_cause;
    emm_sap.u.emm_as.u.establish.nas_info = EMM_AS_NAS_INFO_SR;
    emm_sap.u.emm_as.u.establish.nas_msg = NULL;
    /*
     * Setup EPS NAS security data
     */
    emm_as_set_security_data (&emm_sap.u.emm_as.u.establish.sctx, &emm_context->_security, false, false);
    MSC_LOG_TX_MESSAGE (MSC_NAS_EMM_MME, MSC_NAS_EMM_MME, NULL, 0, "0 EMMAS_ESTABLISH_REJ ue id " MME_UE_S1AP_ID_FMT " ", ue_id);
    rc = emm_sap_send (&emm_sap);
  }

  OAILOG_FUNC_RETURN (LOG_NAS_EMM, rc);
}
