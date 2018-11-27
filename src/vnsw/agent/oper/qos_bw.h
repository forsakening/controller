/*
 * Copyright (c) 2017  Certusnet, Inc. All rights reserved.
 */
#ifndef SRC_VNSW_AGENT_OPER_QOS_BW_HPP_
#define SRC_VNSW_AGENT_OPER_QOS_BW_HPP_

/*****************************************************************************
 * Implements qos manager by this class
 * Sync the qos config to vm_port, FIP and Virtual-Network.
 *****************************************************************************/
#include <cmn/agent_cmn.h>
#include <cmn/agent.h>
#include <agent_types.h>
#include <oper/oper_db.h>

using namespace boost::uuids;
using namespace std;

struct QosBwKey : public AgentOperDBKey {
    QosBwKey(uuid qos_bw_uuid) : AgentOperDBKey(), qos_bw_uuid_(qos_bw_uuid) {} ;
    virtual ~QosBwKey() { };

    uuid qos_bw_uuid_;
};

#define OUTBOUND_BW   0
#define INBOUND_BW    1
#define OUTBOUND_NAME   "egress"
#define INBOUND_NAME   "ingress"

#define MAX_QOS_RULE_NUM 2

struct QosBwRuleData { 
    int max_kbps;
    int max_burst_kbps;
    int direction;
};

typedef struct QosBwRuleData QosBwRuleData_t;
struct QosBwData : public AgentOperDBData {
    QosBwData(Agent *agent, IFMapNode *node, QosBwRuleData rule_data[MAX_QOS_RULE_NUM]) :
                   AgentOperDBData(agent, node) {
        for (int i = 0; i < MAX_QOS_RULE_NUM; i++) {
            rule_data[i] = rule_data[i];
        }
    }
    virtual ~QosBwData() { };
    QosBwRuleData_t rule_data_[MAX_QOS_RULE_NUM];
};

class QosBwEntry : AgentRefCount<QosBwEntry>, public AgentOperDBEntry {
public:
    QosBwEntry(uuid qos_bw_uuid) : qos_bw_uuid_(qos_bw_uuid) { };
    virtual ~QosBwEntry() { };

    virtual bool IsLess(const DBEntry &rhs) const;
    virtual KeyPtr GetDBRequestKey() const;
    virtual void SetKey(const DBRequestKey *key);
    virtual string ToString() const;
    const QosBwRuleData_t* GetQosBwData()     const {
        return rule_data_;
    };
    void  SetQosBwData (QosBwRuleData_t rule_data[])      {
        memcpy(rule_data_, rule_data, sizeof(QosBwRuleData_t)*MAX_QOS_RULE_NUM);
    };
    const uuid &GetQosBwUuid() const {return qos_bw_uuid_;};
    uint32_t GetRefCount() const {
        return AgentRefCount<QosBwEntry>::GetRefCount(); 
    }

    bool DBEntrySandesh(Sandesh *sresp, std::string &name) const;
    void SendObjectLog(SandeshTraceBufferPtr ptr,
                       AgentLogEvent::type event) const;
private:
    friend class QosBwTable;
    uuid qos_bw_uuid_;
    QosBwRuleData_t rule_data_[MAX_QOS_RULE_NUM];
    DISALLOW_COPY_AND_ASSIGN(QosBwEntry);
};

class QosBwTable : public AgentOperDBTable {
public:
    static const uint32_t kInvalidQosBwId = 0;
    QosBwTable(DB *db, const std::string &name) : AgentOperDBTable(db, name) { }
    virtual ~QosBwTable() { }

    virtual std::auto_ptr<DBEntry> AllocEntry(const DBRequestKey *k) const;
    virtual size_t Hash(const DBEntry *entry) const {return 0;};
    virtual size_t  Hash(const DBRequestKey *key) const {return 0;};

    virtual DBEntry *OperDBAdd(const DBRequest *req);
    virtual bool OperDBOnChange(DBEntry *entry, const DBRequest *req);
    virtual bool OperDBDelete(DBEntry *entry, const DBRequest *req);

    virtual bool IFNodeToReq(IFMapNode *node, DBRequest &req,
            const boost::uuids::uuid &u);
    virtual bool IFNodeToUuid(IFMapNode *node, boost::uuids::uuid &u);
    virtual AgentSandeshPtr GetAgentSandesh(const AgentSandeshArguments *args,
                                            const std::string &context);
    bool ProcessConfig(IFMapNode *node, DBRequest &req,
            const boost::uuids::uuid &u);

    static DBTableBase *CreateTable(DB *db, const std::string &name);
    static QosBwTable *GetInstance() {return qos_bw_table_;};

private:
    static QosBwTable* qos_bw_table_;
    bool ChangeHandler(DBEntry *entry, const DBRequest *req);
    DISALLOW_COPY_AND_ASSIGN(QosBwTable);
};


#endif  // SRC_VNSW_AGENT_OPER_QOS_BW_H_
