/*
 * Copyright (c) 2017 CertusNet, Inc. All rights reserved.
 */
#include <algorithm>
#include <boost/uuid/uuid_io.hpp>
#include <base/parse_object.h>
#include <ifmap/ifmap_link.h>
#include <ifmap/ifmap_table.h>
#include <vnc_cfg_types.h>

#include <cmn/agent_cmn.h>
#include <cfg/cfg_init.h>
#include <oper/qos_bw.h>

#include <oper/interface_common.h>
#include <oper/mirror_table.h>
#include <oper/agent_sandesh.h>
#include <oper/config_manager.h>

using namespace autogen;
using namespace std;

QosBwTable *QosBwTable::qos_bw_table_;

bool QosBwEntry::IsLess(const DBEntry &rhs) const {
    const QosBwEntry &a = static_cast<const QosBwEntry &>(rhs);
    return (qos_bw_uuid_ < a.qos_bw_uuid_);
}

string QosBwEntry::ToString() const {
    std::stringstream uuidstring;
    uuidstring << qos_bw_uuid_;
    return uuidstring.str();
}

DBEntryBase::KeyPtr QosBwEntry::GetDBRequestKey() const {
    QosBwKey *key = new QosBwKey(qos_bw_uuid_);
    return DBEntryBase::KeyPtr(key);
}

void QosBwEntry::SetKey(const DBRequestKey *key) {
    const QosBwKey *k = static_cast<const QosBwKey *>(key);
    qos_bw_uuid_ = k->qos_bw_uuid_;
}

std::auto_ptr<DBEntry> QosBwTable::AllocEntry(const DBRequestKey *k) const {
    const QosBwKey *key = static_cast<const QosBwKey *>(k);
    QosBwEntry *qos_bw = new QosBwEntry(key->qos_bw_uuid_);
    QosBwRuleData_t qos_bw_rule_init[MAX_QOS_RULE_NUM] = {{-1,-1,0},{-1,-1,1}};
    qos_bw->SetQosBwData(qos_bw_rule_init);
    return std::auto_ptr<DBEntry>(static_cast<DBEntry *>(qos_bw));
}

DBEntry *QosBwTable::OperDBAdd(const DBRequest *req) {
    QosBwKey *key = static_cast<QosBwKey *>(req->key.get());
    QosBwEntry *qos_bw = new QosBwEntry(key->qos_bw_uuid_);
    ChangeHandler(qos_bw, req);
    qos_bw->SendObjectLog(GetOperDBTraceBuf(), AgentLogEvent::ADD);
    return qos_bw;
}

bool QosBwTable::OperDBOnChange(DBEntry *entry, const DBRequest *req) {
    bool ret = ChangeHandler(entry, req);
    QosBwEntry *qos_bw = static_cast<QosBwEntry *>(entry);
    qos_bw->SendObjectLog(GetOperDBTraceBuf(), AgentLogEvent::CHANGE);
    return ret;
}
//store qos_bw to QosBwEntry from QosBwData
bool QosBwTable::ChangeHandler(DBEntry *entry, const DBRequest *req) {
    bool ret = false;
    QosBwEntry *qos_bw = static_cast<QosBwEntry *>(entry);
    QosBwData *data = static_cast<QosBwData *>(req->data.get());
 
    if (memcmp(qos_bw->GetQosBwData(), data->rule_data_, sizeof(QosBwRuleData_t)*MAX_QOS_RULE_NUM)) {
        qos_bw->SetQosBwData(data->rule_data_);
        ret = true;
    }
    return ret;
}

bool QosBwTable::OperDBDelete(DBEntry *entry, const DBRequest *req) {
    QosBwEntry *qos_bw = static_cast<QosBwEntry *>(entry);
    qos_bw->SendObjectLog(GetOperDBTraceBuf(), AgentLogEvent::DELETE);
    return true;
}

DBTableBase *QosBwTable::CreateTable(DB *db, const std::string &name) {
    qos_bw_table_ = new QosBwTable(db, name);
    qos_bw_table_->Init();
    return qos_bw_table_;
};

bool QosBwTable::IFNodeToUuid(IFMapNode *node, boost::uuids::uuid &u) {
    QosPolicy  *cfg = static_cast<QosPolicy  *>(node->GetObject());
    assert(cfg);
    autogen::IdPermsType id_perms = cfg->id_perms();
    CfgUuidSet(id_perms.uuid.uuid_mslong, id_perms.uuid.uuid_lslong, u);
    return true;
}

bool QosBwTable::IFNodeToReq(IFMapNode *node, DBRequest &req,
        const boost::uuids::uuid &u) {
    QosPolicy  *cfg = static_cast<QosPolicy  *>(node->GetObject());
    assert(cfg);

    assert(!u.is_nil());

    if ((req.oper == DBRequest::DB_ENTRY_DELETE) || node->IsDeleted()) {
        req.oper = DBRequest::DB_ENTRY_DELETE;
        req.key.reset(new QosBwKey(u));
        agent()->qos_bw_table()->Enqueue(&req);
        return false;
    }

    agent()->config_manager()->AddQosBwNode(node);
    return false;
}
//store qos_bw to QosBwData
bool QosBwTable::ProcessConfig(IFMapNode *node, DBRequest &req,
        const boost::uuids::uuid &u) {

    if (node->IsDeleted())
        return false;

    QosPolicy *cfg = static_cast<QosPolicy *>(node->GetObject());
    assert(cfg);

    QosBwKey *key = new QosBwKey(u);
    QosBwData *data  = NULL;
    QosBwRuleData_t qos_bw_rule_cfg[MAX_QOS_RULE_NUM] = {{-1,-1,0},{-1,-1,1}};
    /***********************************
     *index 0 is used to store outbound bw
     *index 1 is used to store inbound  bw
     * default vaule is -1.
     **********************************/
    req.oper = DBRequest::DB_ENTRY_ADD_CHANGE;
    IFMapAgentTable *table = static_cast<IFMapAgentTable *>(node->table());
    for (DBGraphVertex::adjacency_iterator iter =
         node->begin(table->GetGraph());
         iter != node->end(table->GetGraph()); ++iter) {
        IFMapNode *adj_node = static_cast<IFMapNode *>(iter.operator->());
        if (agent()->config_manager()->SkipNode(adj_node)) {
            continue;
        }
        if (adj_node->table() == agent()->cfg()->cfg_qos_bw_table()) {
            QosPolicy *qos_bw_cfg = static_cast<QosPolicy *>
                (adj_node->GetObject());
            assert(qos_bw_cfg);
            int rule_cnt = 0;
            std::vector<QosBandwidthRuleType>::const_iterator  qos_bw_rule_it = qos_bw_cfg->qos_bandwidth_rule_entries().begin();
            while (qos_bw_rule_it != qos_bw_cfg->qos_bandwidth_rule_entries().end()) {
                if ((rule_cnt + 1) > MAX_QOS_RULE_NUM) {
                    assert(0);
                    break;
                }
                if (qos_bw_rule_it->direction == OUTBOUND_NAME) {
                    qos_bw_rule_cfg[OUTBOUND_BW].direction = OUTBOUND_BW;
                    if (qos_bw_rule_it->max_kbps > 0) {
                        qos_bw_rule_cfg[OUTBOUND_BW].max_kbps = qos_bw_rule_it->max_kbps;
                    } else {
                        qos_bw_rule_cfg[OUTBOUND_BW].max_kbps = -1;
                    }
                    if (qos_bw_rule_it->max_burst_kbps > 0) {
                        qos_bw_rule_cfg[OUTBOUND_BW].max_burst_kbps = qos_bw_rule_it->max_burst_kbps;                                   
                    } else {
                        qos_bw_rule_cfg[OUTBOUND_BW].max_burst_kbps = -1;
                    }
                } else if (qos_bw_rule_it->direction == INBOUND_NAME) {
                    qos_bw_rule_cfg[INBOUND_BW].direction = INBOUND_BW;
                    if (qos_bw_rule_it->max_kbps > 0) {
                        qos_bw_rule_cfg[INBOUND_BW].max_kbps = qos_bw_rule_it->max_kbps;
                    } else {
                        qos_bw_rule_cfg[INBOUND_BW].max_kbps = -1;
                    }
                    if (qos_bw_rule_it->max_burst_kbps > 0) {
                        qos_bw_rule_cfg[INBOUND_BW].max_burst_kbps = qos_bw_rule_it->max_burst_kbps;                                   
                    } else {
                        qos_bw_rule_cfg[INBOUND_BW].max_burst_kbps = -1;
                    }
                } else {
                    assert(0);
                }
                qos_bw_rule_it++;
            }
        }
    }
    data = new QosBwData(agent(), node, qos_bw_rule_cfg);
    req.key.reset(key);
    req.data.reset(data);
    agent()->qos_bw_table()->Enqueue(&req);
    return false;
}

bool QosBwEntry::DBEntrySandesh(Sandesh *sresp, std::string &name)  const {

    QosBwListResp *resp = static_cast<QosBwListResp *>(sresp);
    std::string str_uuid = UuidToString(GetQosBwUuid());
    if (name.empty() ||
        (str_uuid == name) ||
        (integerToString(GetQosBwUuid()) == name)) {
        QosBwSandeshData data;
        data.set_ref_count(GetRefCount());
        data.set_qos_bw_uuid(str_uuid);
        std::vector<QosBwSandeshData> &list =
                const_cast<std::vector<QosBwSandeshData>&>(resp->get_qos_bw_list());
        list.push_back(data);
        return true;
    }

    return false;
}

void QosBwEntry::SendObjectLog(SandeshTraceBufferPtr buf, 
                            AgentLogEvent::type event) const {
    QosBwObjectLogInfo info;

    string str;
    switch(event) {
        case AgentLogEvent::ADD:
            str.assign("Addition");
            break;
        case AgentLogEvent::DELETE:
            str.assign("Deletion");
            break;
        case AgentLogEvent::CHANGE:
            str.assign("Modification");
            break;
        default:
            str.assign("");
            break;
    }
    info.set_event(str);

    string qos_bw_uuid = UuidToString(GetQosBwUuid());
    info.set_uuid(qos_bw_uuid);
    info.set_ref_count(GetRefCount());
    QOS_BW_OBJECT_LOG_LOG("AgentQosBw", SandeshLevel::SYS_INFO, info);
    QOS_BW_OBJECT_TRACE_TRACE(buf, info);
}

void QosBwListReq::HandleRequest() const {
    AgentSandeshPtr sand(new AgentQosBwSandesh(context(), get_name()));
    sand->DoSandesh(sand);
}

AgentSandeshPtr QosBwTable::GetAgentSandesh(const AgentSandeshArguments *args,
                                         const std::string &context) {
    return AgentSandeshPtr(new AgentQosBwSandesh(context,
                                              args->GetString("name")));
}


