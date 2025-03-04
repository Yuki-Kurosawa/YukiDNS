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

        [Description("https://icann.org/epp#inactive")]
        Inactive = 3,

        [Description("https://icann.org/epp#ok")]
        Ok = 4,

        [Description("https://icann.org/epp#pendingCreate")]
        PendingCreate = 5,

        [Description("https://icann.org/epp#pendingDelete")]
        PendingDelete = 6,

        [Description("https://icann.org/epp#pendingRenew")]
        PendingRenew = 7,

        [Description("https://icann.org/epp#pendingRestore")]
        PendingRestore = 8,

        [Description("https://icann.org/epp#pendingTransfer")]
        PendingTransfer = 9,

        [Description("https://icann.org/epp#pendingUpdate")]
        PendingUpdate = 10,

        [Description("https://icann.org/epp#redemptionPeriod")]
        RedemptionPeriod = 11,

        [Description("https://icann.org/epp#renewPeriod")]
        RenewPeriod = 12,

        [Description("https://icann.org/epp#serverDeleteProhibited")]
        ServerDeleteProhibited = 13,

        [Description("https://icann.org/epp#serverHold")]
        ServerHold = 14,

        [Description("https://icann.org/epp#serverRenewProhibited")]
        ServerRenewProhibited = 15,

        [Description("https://icann.org/epp#serverTransferProhibited")]
        ServerTransferProhibited = 16,

        [Description("https://icann.org/epp#serverUpdateProhibited")]
        ServerUpdateProhibited = 17,

        [Description("https://icann.org/epp#transferPeriod")]
        TransferPeriod = 18,

        [Description("https://icann.org/epp#clientDeleteProhibited")]
        ClientDeleteProhibited = 19,

        [Description("https://icann.org/epp#clientHold")]
        ClientHold = 20,

        [Description("https://icann.org/epp#clientRenewProhibited")]
        ClientRenewProhibited = 21,

        [Description("https://icann.org/epp#clientTransferProhibited")]
        ClientTransferProhibited = 22,

        [Description("https://icann.org/epp#clientUpdateProhibited")]
        ClientUpdateProhibited = 23


    }
}
