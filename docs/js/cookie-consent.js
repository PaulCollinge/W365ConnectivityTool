/**
 * Microsoft WCP owns the region check, consent cookie, and consent UI.
 * Optional dashboard features stay off until WCP supplies their consent state.
 */
(function () {
    'use strict';

    const libraryUrl = 'https://wcpstatic.microsoft.com/mscc/lib/v2/wcp-consent.js';
    const optionalStorageKeys = [
        'w365-last-mode', 'w365-results-history', 'w365-scanner-results'
    ];
    let siteConsent = null;
    let loading = false;
    let loadTimer;
    let loadAttempt = 0;
    let libraryScript;
    let consentChannel;
    let previousPermissions = null;

    function showStorageError(error) {
        console.warn('Optional dashboard storage is unavailable.', error);
        const warning = document.getElementById('cookie-storage-warning');
        if (warning) warning.hidden = false;
    }

    function removeItem(key) {
        try {
            window.localStorage.removeItem(key);
        } catch (error) {
            showStorageError(error);
        }
    }

    function refreshResources(allowed) {
        document.querySelectorAll('link[data-cookie-href]').forEach(link => {
            if (allowed) {
                if (!link.hasAttribute('href')) link.href = link.dataset.cookieHref;
            } else {
                link.removeAttribute('href');
            }
        });
        document.querySelectorAll('img[data-cookie-src]').forEach(img => {
            applyImageConsent(img, allowed);
        });
    }

    function publishPermissions(storage, resources) {
        refreshResources(resources);
        if (!previousPermissions ||
            previousPermissions.storage !== storage ||
            previousPermissions.resources !== resources) {
            previousPermissions = { storage, resources };
            window.dispatchEvent(new CustomEvent('w365-consent-changed', {
                detail: { storage, resources }
            }));
        }
    }

    function fail(error) {
        ++loadAttempt;
        loading = false;
        siteConsent = null;
        window.clearTimeout(loadTimer);
        console.error('Cookie consent could not be loaded; optional features are disabled.', error);
        const status = document.getElementById('cookie-consent-status');
        const message = document.getElementById('cookie-consent-message');
        const retry = document.getElementById('cookie-consent-retry');
        const manage = document.getElementById('manage-cookies');
        if (status) status.hidden = false;
        if (message) message.textContent =
            'Cookie preferences could not be loaded. Optional saved history and third-party visuals are disabled. You can still run diagnostics.';
        if (retry) retry.hidden = false;
        if (manage) manage.disabled = true;
        publishPermissions(false, false);
    }

    function hasConsent(category) {
        if (!siteConsent) return false;
        try {
            return siteConsent.getConsentFor(category) === true;
        } catch (error) {
            fail(error);
            return false;
        }
    }

    function allowsStorage() {
        return hasConsent('Analytics');
    }

    function allowsResources() {
        return hasConsent('Advertising');
    }

    function getItem(key) {
        if (!allowsStorage()) return null;
        try {
            return window.localStorage.getItem(key);
        } catch (error) {
            showStorageError(error);
            return null;
        }
    }

    function setItem(key, value) {
        if (!allowsStorage()) return false;
        try {
            window.localStorage.setItem(key, value);
            return true;
        } catch (error) {
            showStorageError(error);
            return false;
        }
    }

    function applyImageConsent(img, allowed) {
        img.hidden = !allowed;
        if (allowed) {
            const source = img.dataset.cookieSrc;
            if (img.getAttribute('src') !== source) img.src = source;
        } else {
            img.removeAttribute('src');
        }
    }

    function setImageSource(img, source, deferLoading = false) {
        img.dataset.cookieSrc = source;
        img.crossOrigin = 'anonymous';
        img.referrerPolicy = 'no-referrer';
        applyImageConsent(img, !deferLoading && allowsResources());
    }

    function syncConsent() {
        if (!siteConsent) return;
        const storage = allowsStorage();
        const resources = allowsResources();
        if (!siteConsent) return;

        // Deleting previously saved data does not require reading that data.
        if (!storage) optionalStorageKeys.forEach(removeItem);
        const status = document.getElementById('cookie-consent-status');
        const manage = document.getElementById('manage-cookies');
        const manageControl = document.getElementById('cookie-manage-control');
        if (status) status.hidden = true;
        if (manage) manage.disabled = false;
        if (manageControl) manageControl.hidden = !siteConsent.isConsentRequired;
        publishPermissions(storage, resources);
    }

    function onConsentChanged() {
        syncConsent();
        try {
            if (consentChannel) consentChannel.postMessage('changed');
        } catch (error) {
            console.warn('Could not notify other tabs about changed cookie preferences.', error);
        }
    }

    function initialize() {
        if (loading || siteConsent) return;
        loading = true;
        const attempt = ++loadAttempt;
        const retry = document.getElementById('cookie-consent-retry');
        if (retry) retry.hidden = true;
        loadTimer = window.setTimeout(() => {
            if (attempt === loadAttempt && loading) {
                fail(new Error('The consent component did not initialize within 15 seconds.'));
            }
        }, 15000);

        function initializeWcp() {
            if (attempt !== loadAttempt) return;
            try {
                if (!window.WcpConsent) throw new Error('The WCP consent component is unavailable.');
                window.WcpConsent.init(
                    document.documentElement.lang || 'en-US',
                    'cookie-banner',
                    (error, consent) => {
                        if (attempt !== loadAttempt) return;
                        if (error || !consent) {
                            fail(error || new Error('WCP did not return a consent state.'));
                            return;
                        }
                        window.clearTimeout(loadTimer);
                        loading = false;
                        siteConsent = consent;
                        syncConsent();
                    },
                    onConsentChanged,
                    window.WcpConsent.themes.dark
                );
            } catch (error) {
                fail(error);
            }
        }

        if (window.WcpConsent) {
            initializeWcp();
            return;
        }
        if (libraryScript) libraryScript.remove();
        libraryScript = document.createElement('script');
        libraryScript.src = libraryUrl;
        libraryScript.async = true;
        libraryScript.referrerPolicy = 'no-referrer';
        libraryScript.onload = initializeWcp;
        libraryScript.onerror = () => {
            if (attempt === loadAttempt) fail(new Error('The WCP consent script could not be downloaded.'));
        };
        document.head.appendChild(libraryScript);
    }

    function manage() {
        if (!siteConsent) {
            initialize();
            return;
        }
        try {
            siteConsent.manageConsent();
        } catch (error) {
            fail(error);
        }
    }

    window.DashboardConsent = {
        initialize, manage, allowsStorage, allowsResources,
        getItem, setItem, removeItem, setImageSource,
        refreshResources: () => refreshResources(allowsResources())
    };

    document.addEventListener('DOMContentLoaded', () => {
        try {
            if ('BroadcastChannel' in window) {
                consentChannel = new BroadcastChannel('w365-cookie-consent');
                consentChannel.onmessage = syncConsent;
            }
        } catch (error) {
            console.warn('Cross-tab cookie preference notifications are unavailable.', error);
        }
        initialize();
    });
    window.addEventListener('focus', syncConsent);
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) syncConsent();
    });
})();
