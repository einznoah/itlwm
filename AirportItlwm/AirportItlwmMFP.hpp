//
//  AirportItlwmMFP.hpp
//  AirportItlwm
//
//  802.11w (MFP / PMF) glue between Apple's RSN supplicant and net80211.
//  Shared by the IO80211Controller (pre-Sonoma) and Skywalk (Sonoma+)
//  Apple80211 implementations.
//
//  Unicast robust management frames are protected with the pairwise key
//  (offloaded to firmware by the HAL driver), group addressed management
//  frames are verified with BIP in software using the IGTK.
//

#ifndef AirportItlwmMFP_hpp
#define AirportItlwmMFP_hpp

/*
 * Include after AirportItlwm.hpp / AirportItlwmV2.hpp, which pull in the
 * matching Apple80211 headers (struct apple80211_key) for each target.
 */
#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_priv.h>

/*
 * Release a software crypto context before a key slot is overwritten,
 * otherwise the context allocated by ieee80211_set_key() leaks.
 */
static inline void
itlwm_mfp_release_swkey(struct ieee80211com *ic, struct ieee80211_node *ni,
                        struct ieee80211_key *k)
{
    if (k->k_flags & IEEE80211_KEY_SWCRYPTO)
        ieee80211_delete_key(ic, ni, k);
}

/*
 * Called after the PTK has been installed: from now on robust management
 * frames to/from the AP must be protected if MFP was negotiated.
 */
static inline void
itlwm_mfp_ptk_installed(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    if (ni->ni_flags & IEEE80211_NODE_MFP) {
        ni->ni_flags |= IEEE80211_NODE_RXMGMTPROT |
                        IEEE80211_NODE_TXMGMTPROT;
        XYLog("MFP: management frame protection enabled\n");
    }
}

/*
 * IGTK key identifiers are always 4 or 5 (IEEE 802.11-2020, 12.7.2).
 * Apple's supplicant hands them over through APPLE80211_IOC_CIPHER_KEY like
 * any other group key, so recognise them by their key index.
 */
static inline bool
itlwm_mfp_is_igtk(const struct apple80211_key *key)
{
    return key->key_cipher_type != APPLE80211_CIPHER_NONE &&
           (key->key_index == 4 || key->key_index == 5);
}

static inline void
itlwm_mfp_set_igtk(struct ieee80211com *ic, const u_int8_t *igtk,
                   size_t key_len, u_int8_t kid, const u_int8_t *ipn,
                   size_t ipn_len)
{
    struct ieee80211_node *ni = ic->ic_bss;
    struct ieee80211_key *k;

    if (ni == NULL || !(ni->ni_flags & IEEE80211_NODE_MFP)) {
        XYLog("MFP: ignoring IGTK %d, MFP not negotiated\n", kid);
        return;
    }
    if (ni->ni_rsngroupmgmtcipher != IEEE80211_CIPHER_BIP || key_len != 16) {
        XYLog("MFP: unsupported IGTK %d (cipher=%d len=%zu)\n", kid,
              ni->ni_rsngroupmgmtcipher, key_len);
        return;
    }

    k = &ic->ic_nw_keys[kid];
    if (k->k_cipher == IEEE80211_CIPHER_BIP && k->k_len == key_len &&
        memcmp(k->k_key, igtk, key_len) == 0)
        return; /* retransmitted group key message, keep replay state */

    itlwm_mfp_release_swkey(ic, ni, k);
    memset(k, 0, sizeof(*k));
    k->k_id = kid;
    k->k_cipher = IEEE80211_CIPHER_BIP;
    k->k_flags = IEEE80211_KEY_IGTK;
    if (ipn != NULL && ipn_len >= 6)
        k->k_mgmt_rsc = LE_READ_6(ipn);
    k->k_len = (u_int)key_len;
    memcpy(k->k_key, igtk, key_len);
    if ((*ic->ic_set_key)(ic, ni, k) != 0) {
        XYLog("MFP: setting IGTK %d failed\n", kid);
        return;
    }
    ic->ic_igtk_kid = kid;
    XYLog("MFP: IGTK %d installed\n", kid);
}

#endif /* AirportItlwmMFP_hpp */
