package Utils;


public class Certificate  {
	

	private String certificationAuthorityName;
	private String issuerName;
	private String issuerPublicKey;
	private String domainParameterP;
	private String domainParameterQ;
	private String s1,s2;
	
	
	public Certificate(String certificationAuthorityName, String issuerName, String issuerPublicKey,
			String domainParameterP, String domainParameterQ, String s1, String s2) {
		super();
		this.certificationAuthorityName = certificationAuthorityName;
		this.issuerName = issuerName;
		this.issuerPublicKey = issuerPublicKey;
		this.domainParameterP = domainParameterP;
		this.domainParameterQ = domainParameterQ;
		this.s1 = s1;
		this.s2 = s2;
	}
	
	
	public void setS1(String s1) {
		this.s1 = s1;
	}

	public void setS2(String s2) {
		this.s2 = s2;
	}

	
	public String getIssuerName() {
		return issuerName;
	}


	public String getCertificationAuthorityName() {
		return certificationAuthorityName;
	}


	public void setCertificationAuthorityName(String certificationAuthorityName) {
		this.certificationAuthorityName = certificationAuthorityName;
	}


	public String getIssuerPublicKey() {
		return issuerPublicKey;
	}


	public void setIssuerPublicKey(String issuerPublicKey) {
		this.issuerPublicKey = issuerPublicKey;
	}


	public String getDomainParameterP() {
		return domainParameterP;
	}


	public void setDomainParameterP(String domainParameterP) {
		this.domainParameterP = domainParameterP;
	}


	public String getDomainParameterQ() {
		return domainParameterQ;
	}


	public void setDomainParameterQ(String domainParameterQ) {
		this.domainParameterQ = domainParameterQ;
	}


	public String getS1() {
		return s1;
	}


	public String getS2() {
		return s2;
	}


	public void setIssuerName(String issuerName) {
		this.issuerName = issuerName;
	}


	
	
	
	
	


	
	
	
	
	
	
	
	
	
	
	
	
}
