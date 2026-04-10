package adapter

var deploymentPolicyMatrix = map[SlotName]map[TariffCode]AvailabilityCode{
	SlotPDP: {
		TariffO: AvailActiveAlways,
		TariffS: AvailActiveAlways,
		TariffM: AvailActiveAlways,
		TariffL: AvailActiveAlways,
	},
	SlotOAuthEngine: {
		TariffO: AvailUserProvidedReq,
		TariffS: AvailGimelOrUser,
		TariffM: AvailGimelOrUser,
		TariffL: AvailGimelOrUser,
	},
	SlotFoundry: {
		TariffO: AvailNullOrUser,
		TariffS: AvailGimelOrUser,
		TariffM: AvailGimelOrUser,
		TariffL: AvailGimelOrUser,
	},
	SlotWallet: {
		TariffO: AvailNullOrUser,
		TariffS: AvailGimelOrUser,
		TariffM: AvailGimelOrUser,
		TariffL: AvailGimelOrUser,
	},
	SlotAIGovernance: {
		TariffO: AvailNull,
		TariffS: AvailNull,
		TariffM: AvailAttestedGimel,
		TariffL: AvailAttestedGimel,
	},
	SlotWeb3Identity: {
		TariffO: AvailNull,
		TariffS: AvailNull,
		TariffM: AvailNullOrAttestedGimel,
		TariffL: AvailAttestedGimel,
	},
	SlotDNAIdentity: {
		TariffO: AvailNull,
		TariffS: AvailNull,
		TariffM: AvailNull,
		TariffL: AvailAttestedGimel,
	},
}

func CheckTariffGate(slot SlotName, tariff TariffCode) TariffGateResult {
	matrix, ok := deploymentPolicyMatrix[slot]
	if !ok {
		return TariffGateResult{Allowed: false, Reason: "Unknown slot"}
	}

	availability, ok := matrix[tariff]
	if !ok {
		return TariffGateResult{Allowed: false, Reason: "Unknown tariff code"}
	}

	if availability == AvailNull {
		return TariffGateResult{Allowed: false, Reason: "Slot not available for tariff", Availability: AvailNull}
	}

	typeClass := SlotTypeClass[slot]
	if typeClass == TypeClassC && (tariff == TariffO || tariff == TariffS) {
		return TariffGateResult{Allowed: false, Reason: "Type C requires tariff M or higher", Availability: AvailNull}
	}

	switch availability {
	case AvailActiveAlways:
		return TariffGateResult{Allowed: true, Provenance: "gimel_managed", Availability: availability}
	case AvailGimelOrUser:
		return TariffGateResult{Allowed: true, Provenance: "gimel_or_user", Availability: availability}
	case AvailUserProvidedReq:
		return TariffGateResult{Allowed: true, Provenance: "user_must_provide", Availability: availability}
	case AvailNullOrUser:
		return TariffGateResult{Allowed: true, Provenance: "user_optional", Availability: availability}
	case AvailAttestedGimel:
		return TariffGateResult{Allowed: true, Provenance: "attested_gimel", Availability: availability}
	case AvailNullOrAttestedGimel:
		return TariffGateResult{Allowed: true, Provenance: "null_fallback_until_attested", Availability: availability}
	}

	return TariffGateResult{Allowed: false, Reason: "Unknown availability code"}
}
