using System.ComponentModel;

namespace YukiDNS.WHOIS_CORE
{
    public enum DomainEPPStatus
    {
        [Description("https://icann.org/epp")]
        Unknown = 0,

        [Description("https://icann.org/epp#addPeriod")]
        AddPeriod = 1,

        [Description("https://icann.org/epp#autoRenewPeriod")]
        AutoRenewPeriod = 2,

        [Description("https://icann.org/epp#inactive"), RdapStatus("inactive")]
        Inactive = 3,

        [Description("https://icann.org/epp#ok"), RdapStatus("active")]
        Ok = 4,

        [Description("https://icann.org/epp#pendingCreate"), RdapStatus("pending create")]
        PendingCreate = 5,

        [Description("https://icann.org/epp#pendingDelete"), RdapStatus("pending delete")]
        PendingDelete = 6,

        [Description("https://icann.org/epp#pendingRenew"), RdapStatus("pending renew")]
        PendingRenew = 7,

        [Description("https://icann.org/epp#pendingRestore"), RdapStatus("pending update")]
        PendingRestore = 8,

        [Description("https://icann.org/epp#pendingTransfer"), RdapStatus("pending transfer")]
        PendingTransfer = 9,

        [Description("https://icann.org/epp#pendingUpdate"), RdapStatus("pending update")]
        PendingUpdate = 10,

        [Description("https://icann.org/epp#redemptionPeriod"), RdapStatus("inactive")]
        RedemptionPeriod = 11,

        [Description("https://icann.org/epp#renewPeriod"), RdapStatus("inactive")]
        RenewPeriod = 12,

        [Description("https://icann.org/epp#serverDeleteProhibited"), RdapStatus("delete prohibited")]
        ServerDeleteProhibited = 13,

        [Description("https://icann.org/epp#serverHold"), RdapStatus("inactive")]
        ServerHold = 14,

        [Description("https://icann.org/epp#serverRenewProhibited"), RdapStatus("renew prohibited")]
        ServerRenewProhibited = 15,

        [Description("https://icann.org/epp#serverTransferProhibited"), RdapStatus("transfer prohibited")]
        ServerTransferProhibited = 16,

        [Description("https://icann.org/epp#serverUpdateProhibited"), RdapStatus("update prohibited")]
        ServerUpdateProhibited = 17,

        [Description("https://icann.org/epp#transferPeriod"), RdapStatus("inactive")]
        TransferPeriod = 18,

        [Description("https://icann.org/epp#clientDeleteProhibited"), RdapStatus("delete prohibited")]
        ClientDeleteProhibited = 19,

        [Description("https://icann.org/epp#clientHold"), RdapStatus("inactive")]
        ClientHold = 20,

        [Description("https://icann.org/epp#clientRenewProhibited"), RdapStatus("renew prohibited")]
        ClientRenewProhibited = 21,

        [Description("https://icann.org/epp#clientTransferProhibited"), RdapStatus("transfer prohibited")]
        ClientTransferProhibited = 22,

        [Description("https://icann.org/epp#clientUpdateProhibited"), RdapStatus("update prohibited")]
        ClientUpdateProhibited = 23


    }
}
