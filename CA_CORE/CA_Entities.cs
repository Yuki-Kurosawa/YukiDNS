namespace YukiDNS.CA_CORE
{
    public class InitRootCARequest
    {
        public string Name { get; set; }
    }

    public class Layer2Request
    {
        public string Name { get; set; }
        public string CAName { get; set; }
    }
}
