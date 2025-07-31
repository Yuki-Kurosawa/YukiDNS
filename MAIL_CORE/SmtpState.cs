namespace YukiDNS.MAIL_CORE
{
    public enum SmtpState
    {
        Initial,
        DataMode,
        HeloReceived,
        MailFromReceived,
        RcptToReceived
    }
}
