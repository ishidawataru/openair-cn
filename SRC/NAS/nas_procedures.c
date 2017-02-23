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

/*! \file nas_procedures.c
   \brief
   \author  Lionel GAUTHIER
   \date 2017
   \email: lionel.gauthier@eurecom.fr
*/


#include <pthread.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "bstrlib.h"

#include "gcc_diag.h"
#include "dynamic_memory_check.h"
#include "assertions.h"
#include "log.h"
#include "msc.h"
#include "nas_timer.h"
#include "common_types.h"
#include "3gpp_24.008.h"
#include "3gpp_36.401.h"
#include "3gpp_29.274.h"
#include "conversions.h"
#include "3gpp_requirements_24.301.h"
#include "nas_message.h"
#include "as_message.h"
#include "mme_app_ue_context.h"
#include "emm_proc.h"
#include "networkDef.h"
#include "emm_sap.h"
#include "mme_api.h"
#include "emm_data.h"
#include "esm_proc.h"
#include "esm_sapDef.h"
#include "esm_sap.h"
#include "emm_cause.h"
#include "NasSecurityAlgorithms.h"
#include "mme_config.h"
#include "nas_itti_messaging.h"
#include "mme_app_defs.h"
#include "nas_procedures.h"

static  nas_emm_common_proc_t *get_nas_common_procedure(const struct emm_context_s * const ctxt, emm_common_proc_type_t proc_type);
static  nas_cn_proc_t *get_nas_cn_procedure(const struct emm_context_s * const ctxt, cn_proc_type_t proc_type);

static void nas_emm_procedure_gc(struct emm_context_s * const emm_context);
static void nas_delete_con_mngt_procedure(nas_emm_con_mngt_proc_t **  proc);
static void nas_delete_auth_info_procedure(struct emm_context_s *emm_context, nas_auth_info_proc_t ** auth_info_proc);
static void nas_delete_child_procedures(struct emm_context_s * const emm_context, nas_base_proc_t * const parent_proc);
static void nas_delete_cn_procedures(struct emm_context_s *emm_context);
static void nas_delete_common_procedures(struct emm_context_s *emm_context);



//------------------------------------------------------------------------------
static  nas_emm_common_proc_t *get_nas_common_procedure(const struct emm_context_s * const ctxt, emm_common_proc_type_t proc_type)
{
  if (ctxt) {
    if (ctxt->emm_procedures) {
      nas_emm_common_procedure_t *p1 = LIST_FIRST(&ctxt->emm_procedures->emm_common_procs);
      nas_emm_common_procedure_t *p2 = NULL;
      while (p1) {
        p2 = LIST_NEXT(p1, entries);
        if (p1->proc->type == proc_type) {
          return p1->proc;
        }
        p1 = p2;
      }
    }
  }
  return NULL;
}
//------------------------------------------------------------------------------
static  nas_cn_proc_t *get_nas_cn_procedure(const struct emm_context_s * const ctxt, cn_proc_type_t proc_type)
{
  if (ctxt) {
    if (ctxt->emm_procedures) {
      nas_cn_procedure_t *p1 = LIST_FIRST(&ctxt->emm_procedures->cn_procs);
      nas_cn_procedure_t *p2 = NULL;
      while (p1) {
        p2 = LIST_NEXT(p1, entries);
        if (p1->proc->type == proc_type) {
          return p1->proc;
        }
        p1 = p2;
      }
    }
  }
  return NULL;
}
//------------------------------------------------------------------------------
inline bool is_nas_common_procedure_guti_realloc_running(const struct emm_context_s * const ctxt)
{
  if (get_nas_common_procedure_guti_realloc(ctxt)) return true;
  return false;
}

//------------------------------------------------------------------------------
inline bool is_nas_common_procedure_authentication_running(const struct emm_context_s * const ctxt)
{
  if (get_nas_common_procedure_authentication(ctxt)) return true;
  return false;
}

//------------------------------------------------------------------------------
inline bool is_nas_common_procedure_smc_running(const struct emm_context_s * const ctxt)
{
  if (get_nas_common_procedure_smc(ctxt)) return true;
  return false;
}

//------------------------------------------------------------------------------
inline bool is_nas_common_procedure_identification_running(const struct emm_context_s * const ctxt)
{
  if (get_nas_common_procedure_identification(ctxt)) return true;
  return false;
}

//------------------------------------------------------------------------------
nas_emm_guti_proc_t *get_nas_common_procedure_guti_realloc(const struct emm_context_s * const ctxt)
{
  return (nas_emm_guti_proc_t*)get_nas_common_procedure(ctxt, EMM_COMM_PROC_GUTI);
}

//------------------------------------------------------------------------------
nas_emm_auth_proc_t *get_nas_common_procedure_authentication(const struct emm_context_s * const ctxt)
{
  return (nas_emm_auth_proc_t*)get_nas_common_procedure(ctxt, EMM_COMM_PROC_AUTH);
}

//------------------------------------------------------------------------------
nas_auth_info_proc_t *get_nas_cn_procedure_auth_info(const struct emm_context_s * const ctxt)
{
  return (nas_auth_info_proc_t*)get_nas_cn_procedure(ctxt, CN_PROC_AUTH_INFO);
}

//------------------------------------------------------------------------------
nas_emm_smc_proc_t *get_nas_common_procedure_smc(const struct emm_context_s * const ctxt)
{
  return (nas_emm_smc_proc_t*)get_nas_common_procedure(ctxt, EMM_COMM_PROC_SMC);
}

//------------------------------------------------------------------------------
nas_emm_ident_proc_t *get_nas_common_procedure_identification(const struct emm_context_s * const ctxt)
{
  return (nas_emm_ident_proc_t*)get_nas_common_procedure(ctxt, EMM_COMM_PROC_IDENT);
}

//------------------------------------------------------------------------------
inline bool is_nas_specific_procedure_attach_running(const struct emm_context_s * const ctxt)
{
  if ((ctxt) && (ctxt->emm_procedures)  && (ctxt->emm_procedures->emm_specific_proc) &&
      ((EMM_SPEC_PROC_TYPE_ATTACH == ctxt->emm_procedures->emm_specific_proc->type))) return true;
  return false;
}

//-----------------------------------------------------------------------------
inline bool is_nas_specific_procedure_detach_running(const struct emm_context_s * const ctxt)
{
  if ((ctxt) && (ctxt->emm_procedures)  && (ctxt->emm_procedures->emm_specific_proc) &&
      ((EMM_SPEC_PROC_TYPE_DETACH == ctxt->emm_procedures->emm_specific_proc->type))) return true;
  return false;
}

//-----------------------------------------------------------------------------
inline bool is_nas_specific_procedure_tau_running(const struct emm_context_s * const ctxt)
{
  if ((ctxt) && (ctxt->emm_procedures)  && (ctxt->emm_procedures->emm_specific_proc) &&
      ((EMM_SPEC_PROC_TYPE_TAU == ctxt->emm_procedures->emm_specific_proc->type))) return true;
  return false;
}

//------------------------------------------------------------------------------
nas_emm_attach_proc_t *get_nas_specific_procedure_attach(const struct emm_context_s * const ctxt)
{
  if ((ctxt) && (ctxt->emm_procedures)  && (ctxt->emm_procedures->emm_specific_proc) &&
      ((EMM_SPEC_PROC_TYPE_ATTACH == ctxt->emm_procedures->emm_specific_proc->type))) return (nas_emm_attach_proc_t *)ctxt->emm_procedures->emm_specific_proc;
  return NULL;
}

//-----------------------------------------------------------------------------
nas_emm_detach_proc_t *get_nas_specific_procedure_detach(const struct emm_context_s * const ctxt)
{
  if ((ctxt) && (ctxt->emm_procedures)  && (ctxt->emm_procedures->emm_specific_proc) &&
      ((EMM_SPEC_PROC_TYPE_DETACH == ctxt->emm_procedures->emm_specific_proc->type))) return (nas_emm_detach_proc_t *)ctxt->emm_procedures->emm_specific_proc;
  return NULL;
}

//-----------------------------------------------------------------------------
nas_emm_tau_proc_t *get_nas_specific_procedure_tau(const struct emm_context_s * const ctxt)
{
  if ((ctxt) && (ctxt->emm_procedures)  && (ctxt->emm_procedures->emm_specific_proc) &&
      ((EMM_SPEC_PROC_TYPE_TAU == ctxt->emm_procedures->emm_specific_proc->type))) return (nas_emm_tau_proc_t *)ctxt->emm_procedures->emm_specific_proc;
  return NULL;
}

//------------------------------------------------------------------------------
nas_sr_proc_t *get_nas_con_mngt_procedure_service_request(const struct emm_context_s * const ctxt)
{
  if ((ctxt) && (ctxt->emm_procedures)  && (ctxt->emm_procedures->emm_con_mngt_proc) &&
      ((EMM_CON_MNGT_PROC_SERVICE_REQUEST == ctxt->emm_procedures->emm_con_mngt_proc->type))) return (nas_sr_proc_t *)ctxt->emm_procedures->emm_con_mngt_proc;
  return NULL;
}


//-----------------------------------------------------------------------------
inline bool is_nas_attach_accept_sent(const nas_emm_attach_proc_t * const attach_proc)
{
  if (attach_proc->attach_accept_sent) {
    return true;
  } else {
    return false;
  }
}
//-----------------------------------------------------------------------------
inline bool is_nas_attach_reject_sent(const nas_emm_attach_proc_t * const attach_proc)
{
  return attach_proc->attach_reject_sent;
}
//-----------------------------------------------------------------------------
inline bool is_nas_attach_complete_received(const nas_emm_attach_proc_t * const attach_proc)
{
  return attach_proc->attach_complete_received;
}


//------------------------------------------------------------------------------
int nas_unlink_procedures(nas_base_proc_t * const parent_proc, nas_base_proc_t * const child_proc)
{
  if ((parent_proc) && (child_proc)) {
    if ((parent_proc->child == child_proc) && (child_proc->parent == parent_proc)) {
      child_proc->parent = NULL;
      parent_proc->child = NULL;
      return RETURNok;
    }
  }
  return RETURNerror;
}

//-----------------------------------------------------------------------------
static void nas_emm_procedure_gc(struct emm_context_s * const emm_context)
{
  if ( LIST_EMPTY(&emm_context->emm_procedures->emm_common_procs) &&
       LIST_EMPTY(&emm_context->emm_procedures->cn_procs) &&
       (!emm_context->emm_procedures->emm_con_mngt_proc) &&
       (!emm_context->emm_procedures->emm_specific_proc) ) {
    free_wrapper((void**)&emm_context->emm_procedures);
  }
}
//-----------------------------------------------------------------------------
static void nas_delete_child_procedures(struct emm_context_s * const emm_context, nas_base_proc_t * const parent_proc)
{
  // abort child procedures
  if (emm_context->emm_procedures) {
    nas_emm_common_procedure_t *p1 = LIST_FIRST(&emm_context->emm_procedures->emm_common_procs);
    nas_emm_common_procedure_t *p2 = NULL;
    while (p1) {
      p2 = LIST_NEXT(p1, entries);
      if (((nas_base_proc_t *)p1->proc)->parent == parent_proc) {
        nas_delete_common_procedure(emm_context, &p1->proc);
        LIST_REMOVE(p1, entries);
        free_wrapper((void**)&p1);
      }
      p1 = p2;
    }

    if (emm_context->emm_procedures->emm_con_mngt_proc) {
      if (((nas_base_proc_t *)(emm_context->emm_procedures->emm_con_mngt_proc))->parent == parent_proc) {
        nas_delete_con_mngt_procedure(&emm_context->emm_procedures->emm_con_mngt_proc);
      }
    }
  }
}

//-----------------------------------------------------------------------------
static void nas_delete_con_mngt_procedure(nas_emm_con_mngt_proc_t **  proc)
{
  if (*proc) {
    AssertFatal(0, "TODO");
    free_wrapper((void**)proc);
  }
}
//-----------------------------------------------------------------------------
void nas_delete_common_procedure(struct emm_context_s *emm_context, nas_emm_common_proc_t **  proc)
{
  if (*proc) {
    // free proc content
    switch ((*proc)->type) {
      case EMM_COMM_PROC_GUTI:
        break;
      case EMM_COMM_PROC_AUTH: {
          nas_emm_auth_proc_t *auth_info_proc = (nas_emm_auth_proc_t *)(*proc);
          if (auth_info_proc->unchecked_imsi) {
            free_wrapper((void**)&auth_info_proc->unchecked_imsi);
          }
        }
        break;
      case EMM_COMM_PROC_SMC: {
          //nas_emm_smc_proc_t *smc_proc = (nas_emm_smc_proc_t *)(*proc);
        }
        break;
      case EMM_COMM_PROC_IDENT: {
          //nas_emm_ident_proc_t *ident_proc = (nas_emm_ident_proc_t *)(*proc);
        }
        break;
      case EMM_COMM_PROC_INFO:
        break;
      default: ;
    }

    // remove proc from list
    if (emm_context->emm_procedures) {
      nas_emm_common_procedure_t *p1 = LIST_FIRST(&emm_context->emm_procedures->emm_common_procs);
      nas_emm_common_procedure_t *p2 = NULL;
      // 2 methods: this one, the other: use parent struct macro and LIST_REMOVE without searching matching element in the list
      while (p1) {
        p2 = LIST_NEXT(p1, entries);
        if (p1->proc == (nas_emm_common_proc_t*)(*proc)) {
          LIST_REMOVE(p1, entries);
          free_wrapper((void**)&p1->proc);
          free_wrapper((void**)&p1);
          *proc = NULL;
          return;
        }
        p1 = p2;
      }
      nas_emm_procedure_gc(emm_context);
    }
    // if not found in list, free it anyway
    if (*proc) {
      free_wrapper((void**)proc);
    }
  }
}

//-----------------------------------------------------------------------------
static void nas_delete_common_procedures(struct emm_context_s *emm_context)
{
  // remove proc from list
  if (emm_context->emm_procedures) {
    nas_emm_common_procedure_t *p1 = LIST_FIRST(&emm_context->emm_procedures->emm_common_procs);
    nas_emm_common_procedure_t *p2 = NULL;
    while (p1) {
      p2 = LIST_NEXT(p1, entries);
      LIST_REMOVE(p1, entries);

      switch (p1->proc->type) {
        case EMM_COMM_PROC_GUTI:
          break;
        case EMM_COMM_PROC_AUTH: {
            nas_emm_auth_proc_t *auth_info_proc = (nas_emm_auth_proc_t *)p1->proc;
            if (auth_info_proc->unchecked_imsi) {
              free_wrapper((void**)&auth_info_proc->unchecked_imsi);
            }
          }
          break;
        case EMM_COMM_PROC_SMC: {
            //nas_emm_smc_proc_t *smc_proc = (nas_emm_smc_proc_t *)(*proc);
          }
          break;
        case EMM_COMM_PROC_IDENT: {
            //nas_emm_ident_proc_t *ident_proc = (nas_emm_ident_proc_t *)(*proc);
          }
          break;
        case EMM_COMM_PROC_INFO:
          break;
        default: ;
      }

      free_wrapper((void**)&p1->proc);
      free_wrapper((void**)&p1);

      p1 = p2;
    }
    nas_emm_procedure_gc(emm_context);
  }
}

//-----------------------------------------------------------------------------
void nas_delete_attach_procedure(struct emm_context_s *emm_context)
{
  nas_emm_attach_proc_t     *proc = get_nas_specific_procedure_attach(emm_context);
  if (proc) {
    // free content
    mme_ue_s1ap_id_t      ue_id = PARENT_STRUCT(emm_context, struct ue_mm_context_s, emm_context)->mme_ue_s1ap_id;
    void *unused = NULL;
    nas_stop_T3450(ue_id, &proc->T3450, unused);
    if (proc->ies) {
      free_emm_attach_request_ies(&proc->ies);
    }
    if (proc->esm_msg_out) {
      bdestroy_wrapper(&proc->esm_msg_out);
    }

    nas_delete_child_procedures(emm_context, (nas_base_proc_t *)proc);

    free_wrapper((void**)&emm_context->emm_procedures->emm_specific_proc);
    nas_emm_procedure_gc(emm_context);
  }
}
//-----------------------------------------------------------------------------
void nas_delete_tau_procedure(struct emm_context_s *emm_context)
{
  nas_emm_tau_proc_t     *proc = get_nas_specific_procedure_tau(emm_context);
  if (proc) {
    // free content
    mme_ue_s1ap_id_t      ue_id = PARENT_STRUCT(emm_context, struct ue_mm_context_s, emm_context)->mme_ue_s1ap_id;
    void *unused = NULL;
    nas_stop_T3450(ue_id, &proc->T3450, unused);
    if (proc->ies) {
      free_emm_tau_request_ies(&proc->ies);
    }
    if (proc->esm_msg_out) {
      bdestroy_wrapper(&proc->esm_msg_out);
    }

    nas_delete_child_procedures(emm_context, (nas_base_proc_t *)proc);

    free_wrapper((void**)&emm_context->emm_procedures->emm_specific_proc);
    nas_emm_procedure_gc(emm_context);
  }
}
//-----------------------------------------------------------------------------
void nas_delete_detach_procedure(struct emm_context_s *emm_context)
{
  nas_emm_detach_proc_t     *proc = get_nas_specific_procedure_detach(emm_context);
  if (proc) {
    // free content
    if (proc->ies) {
      free_emm_detach_request_ies(&proc->ies);
    }

    nas_delete_child_procedures(emm_context, (nas_base_proc_t *)proc);

    free_wrapper((void**)&emm_context->emm_procedures->emm_specific_proc);
    nas_emm_procedure_gc(emm_context);
  }
}


//-----------------------------------------------------------------------------
static void nas_delete_auth_info_procedure(struct emm_context_s *emm_context, nas_auth_info_proc_t ** auth_info_proc)
{
  if (*auth_info_proc) {
    if ((*auth_info_proc)->cn_proc.base_proc.parent) {
      (*auth_info_proc)->cn_proc.base_proc.parent->child = NULL;
    }
    free_wrapper((void**)auth_info_proc);
  }
}

//-----------------------------------------------------------------------------
void nas_delete_cn_procedure(struct emm_context_s *emm_context, nas_cn_proc_t * cn_proc)
{
  if (emm_context->emm_procedures) {
    nas_cn_procedure_t *p1 = LIST_FIRST(&emm_context->emm_procedures->cn_procs);
    nas_cn_procedure_t *p2 = NULL;
    // 2 methods: this one, the other: use parent struct macro and LIST_REMOVE without searching matching element in the list
    while (p1) {
      p2 = LIST_NEXT(p1, entries);
      if (p1->proc == cn_proc) {
        switch (cn_proc->type) {
          case CN_PROC_AUTH_INFO:
            nas_delete_auth_info_procedure(emm_context, (nas_auth_info_proc_t**)&cn_proc);
            break;
          case CN_PROC_NONE:
            free_wrapper((void**)&cn_proc);
            break;
          default:;
        }
        LIST_REMOVE(p1, entries);
        free_wrapper((void**)&p1);
        return;
      }
      p1 = p2;
    }
    nas_emm_procedure_gc(emm_context);
  }
}

//-----------------------------------------------------------------------------
static void nas_delete_cn_procedures(struct emm_context_s *emm_context)
{
  if (emm_context->emm_procedures) {
    nas_cn_procedure_t *p1 = LIST_FIRST(&emm_context->emm_procedures->cn_procs);
    nas_cn_procedure_t *p2 = NULL;
    while (p1) {
      p2 = LIST_NEXT(p1, entries);
      switch (p1->proc->type) {
        case CN_PROC_AUTH_INFO:
          nas_delete_auth_info_procedure(emm_context, (nas_auth_info_proc_t**)&p1->proc);
          break;

        default:
          free_wrapper((void**)&p1->proc);
      }
      LIST_REMOVE(p1, entries);
      free_wrapper((void**)&p1);
      p1 = p2;
    }
    nas_emm_procedure_gc(emm_context);
  }
}


//-----------------------------------------------------------------------------
void nas_delete_all_emm_procedures(struct emm_context_s * const emm_context)
{
  if (emm_context->emm_procedures) {

    nas_delete_cn_procedures(emm_context);
    nas_delete_common_procedures(emm_context);
    //TODO nas_delete_con_mngt_procedure(emm_context);
    nas_delete_attach_procedure(emm_context);
    nas_delete_detach_procedure(emm_context);
    nas_delete_tau_procedure(emm_context);

    free_wrapper((void**)&emm_context->emm_procedures);
  }
}

//-----------------------------------------------------------------------------
static emm_procedures_t *_nas_new_emm_procedures(struct emm_context_s * const emm_context)
{
  emm_procedures_t *emm_procedures = calloc(1, sizeof(*emm_context->emm_procedures));
  LIST_INIT(&emm_context->emm_procedures->emm_common_procs);
  return emm_procedures;
}

//-----------------------------------------------------------------------------
nas_emm_attach_proc_t* nas_new_attach_procedure(struct emm_context_s * const emm_context)
{
  if (!(emm_context->emm_procedures)) {
    emm_context->emm_procedures = _nas_new_emm_procedures(emm_context);
  } else if (emm_context->emm_procedures->emm_specific_proc) {
    OAILOG_ERROR (LOG_NAS_EMM,
        "UE " MME_UE_S1AP_ID_FMT " Attach procedure creation requested but another specific procedure found\n", PARENT_STRUCT(emm_context, struct ue_mm_context_s, emm_context)->mme_ue_s1ap_id);
    return NULL;
  }
  emm_context->emm_procedures->emm_specific_proc = calloc(1, sizeof(nas_emm_attach_proc_t));

  ((nas_base_proc_t*)(emm_context->emm_procedures->emm_specific_proc))->type = NAS_PROC_TYPE_EMM;
  ((nas_emm_proc_t*)(emm_context->emm_procedures->emm_specific_proc))->type  = NAS_EMM_PROC_TYPE_SPECIFIC;
  ((nas_emm_specific_proc_t*)(emm_context->emm_procedures->emm_specific_proc))->type  = EMM_SPEC_PROC_TYPE_ATTACH;

  nas_emm_attach_proc_t * proc = (nas_emm_attach_proc_t*)emm_context->emm_procedures->emm_specific_proc;

  proc->T3450.sec       = mme_config.nas_config.t3450_sec;
  proc->T3450.id        = NAS_TIMER_INACTIVE_ID;

  return proc;
}

//-----------------------------------------------------------------------------
nas_emm_tau_proc_t *nas_new_tau_procedure(struct emm_context_s * const emm_context)
{
  if (!(emm_context->emm_procedures)) {
    emm_context->emm_procedures = _nas_new_emm_procedures(emm_context);
  } else if (emm_context->emm_procedures->emm_specific_proc) {
    OAILOG_ERROR (LOG_NAS_EMM,
        "UE " MME_UE_S1AP_ID_FMT " Attach procedure creation requested but another specific procedure found\n", PARENT_STRUCT(emm_context, struct ue_mm_context_s, emm_context)->mme_ue_s1ap_id);
    return NULL;
  }
  emm_context->emm_procedures->emm_specific_proc = calloc(1, sizeof(nas_emm_tau_proc_t));

  ((nas_base_proc_t*)(emm_context->emm_procedures->emm_specific_proc))->type = NAS_PROC_TYPE_EMM;
  ((nas_emm_proc_t*)(emm_context->emm_procedures->emm_specific_proc))->type  = NAS_EMM_PROC_TYPE_SPECIFIC;
  ((nas_emm_specific_proc_t*)(emm_context->emm_procedures->emm_specific_proc))->type  = EMM_SPEC_PROC_TYPE_TAU;

  nas_emm_tau_proc_t * proc = (nas_emm_tau_proc_t*)emm_context->emm_procedures->emm_specific_proc;

  proc->T3450.sec       = mme_config.nas_config.t3450_sec;
  proc->T3450.id        = NAS_TIMER_INACTIVE_ID;

  return proc;
}

//-----------------------------------------------------------------------------
nas_sr_proc_t* nas_new_service_request_procedure(struct emm_context_s * const emm_context)
{
  if (!(emm_context->emm_procedures)) {
    emm_context->emm_procedures = _nas_new_emm_procedures(emm_context);
  } else if (emm_context->emm_procedures->emm_con_mngt_proc) {
    OAILOG_ERROR (LOG_NAS_EMM,
        "UE " MME_UE_S1AP_ID_FMT " SR procedure creation requested but another connection management procedure found\n", PARENT_STRUCT(emm_context, struct ue_mm_context_s, emm_context)->mme_ue_s1ap_id);
    return NULL;
  }
  emm_context->emm_procedures->emm_con_mngt_proc = calloc(1, sizeof(nas_sr_proc_t));

  ((nas_base_proc_t*)(emm_context->emm_procedures->emm_con_mngt_proc))->type = NAS_PROC_TYPE_EMM;
  ((nas_emm_proc_t*)(emm_context->emm_procedures->emm_con_mngt_proc))->type  = NAS_EMM_PROC_TYPE_CONN_MNGT;
  ((nas_emm_con_mngt_proc_t*)(emm_context->emm_procedures->emm_con_mngt_proc))->type  = EMM_CON_MNGT_PROC_SERVICE_REQUEST;

  nas_sr_proc_t * proc = (nas_sr_proc_t*)emm_context->emm_procedures->emm_con_mngt_proc;

  return proc;
}

//-----------------------------------------------------------------------------
nas_emm_ident_proc_t *nas_new_identification_procedure(struct emm_context_s * const emm_context)
{
  if (!(emm_context->emm_procedures)) {
    emm_context->emm_procedures = _nas_new_emm_procedures(emm_context);
  }

  nas_emm_ident_proc_t * ident_proc =  calloc(1, sizeof(nas_emm_ident_proc_t));

  ident_proc->emm_com_proc.emm_proc.base_proc.type = NAS_PROC_TYPE_EMM;
  ident_proc->emm_com_proc.emm_proc.type      = NAS_EMM_PROC_TYPE_COMMON;
  ident_proc->emm_com_proc.type           = EMM_COMM_PROC_IDENT;

  ident_proc->T3470.sec       = mme_config.nas_config.t3470_sec;
  ident_proc->T3470.id        = NAS_TIMER_INACTIVE_ID;

  nas_emm_common_procedure_t * wrapper = calloc(1, sizeof(*wrapper));
  if (wrapper) {
    wrapper->proc = &ident_proc->emm_com_proc;
    LIST_INSERT_HEAD(&emm_context->emm_procedures->emm_common_procs, wrapper, entries);
    return ident_proc;
  } else {
    free_wrapper((void**)&ident_proc);
  }
  return ident_proc;
}

//-----------------------------------------------------------------------------
nas_emm_auth_proc_t *nas_new_authentication_procedure(struct emm_context_s * const emm_context)
{
  if (!(emm_context->emm_procedures)) {
    emm_context->emm_procedures = _nas_new_emm_procedures(emm_context);
  }

  nas_emm_auth_proc_t * auth_proc =  calloc(1, sizeof(nas_emm_auth_proc_t));

  auth_proc->emm_com_proc.emm_proc.base_proc.type = NAS_PROC_TYPE_EMM;
  auth_proc->emm_com_proc.emm_proc.type      = NAS_EMM_PROC_TYPE_COMMON;
  auth_proc->emm_com_proc.type           = EMM_COMM_PROC_AUTH;

  auth_proc->T3460.sec       = mme_config.nas_config.t3460_sec;
  auth_proc->T3460.id        = NAS_TIMER_INACTIVE_ID;

  nas_emm_common_procedure_t * wrapper = calloc(1, sizeof(*wrapper));
  if (wrapper) {
    wrapper->proc = &auth_proc->emm_com_proc;
    LIST_INSERT_HEAD(&emm_context->emm_procedures->emm_common_procs, wrapper, entries);
    return auth_proc;
  } else {
    free_wrapper((void**)&auth_proc);
  }
  return NULL;
}

//-----------------------------------------------------------------------------
nas_emm_smc_proc_t *nas_new_smc_procedure(struct emm_context_s * const emm_context)
{
  if (!(emm_context->emm_procedures)) {
    emm_context->emm_procedures = _nas_new_emm_procedures(emm_context);
  }

  nas_emm_smc_proc_t * smc_proc =  calloc(1, sizeof(nas_emm_smc_proc_t));

  smc_proc->emm_com_proc.emm_proc.base_proc.type = NAS_PROC_TYPE_EMM;
  smc_proc->emm_com_proc.emm_proc.type      = NAS_EMM_PROC_TYPE_COMMON;
  smc_proc->emm_com_proc.type               = EMM_COMM_PROC_SMC;

  smc_proc->T3460.sec       = mme_config.nas_config.t3460_sec;
  smc_proc->T3460.id        = NAS_TIMER_INACTIVE_ID;

  nas_emm_common_procedure_t * wrapper = calloc(1, sizeof(*wrapper));
  if (wrapper) {
    wrapper->proc = &smc_proc->emm_com_proc;
    LIST_INSERT_HEAD(&emm_context->emm_procedures->emm_common_procs, wrapper, entries);
    return smc_proc;
  } else {
    free_wrapper((void**)&smc_proc);
  }
  return NULL;
}

//-----------------------------------------------------------------------------
nas_auth_info_proc_t *nas_new_cn_auth_info_procedure(struct emm_context_s * const emm_context)
{
  if (!(emm_context->emm_procedures)) {
    emm_context->emm_procedures = _nas_new_emm_procedures(emm_context);
  }

  nas_auth_info_proc_t * auth_info_proc =  calloc(1, sizeof(nas_auth_info_proc_t));

  auth_info_proc->cn_proc.base_proc.type = NAS_PROC_TYPE_CN;
  auth_info_proc->cn_proc.type           = CN_PROC_AUTH_INFO;


  nas_cn_procedure_t * wrapper = calloc(1, sizeof(*wrapper));
  if (wrapper) {
    wrapper->proc = &auth_info_proc->cn_proc;
    LIST_INSERT_HEAD(&emm_context->emm_procedures->cn_procs, wrapper, entries);
    return auth_info_proc;
  } else {
    free_wrapper((void**)&auth_info_proc);
  }
  return NULL;
}
