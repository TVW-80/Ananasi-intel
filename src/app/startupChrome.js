import { initFirstRunExperience } from '../firstRunExperience.js';
import { initLoginReport } from '../anansi/loginReport.js';
import { initAjeAlert } from '../anansi/ajeAlert.js';

/** Reveal welcome controls only after restoration and the loading transition. */
export function startApplicationChrome({
  loadingScreen,
  styleManager,
  dataManager,
  signal,
  initializeWelcome = initFirstRunExperience,
  initializeLoginReport,
  initializeSettings,
}) {
  let disposed = false;
  let firstRun;
  let loginReport;
  let ajeAlert;
  let revealTimer;
  // Anansi: the "since you were last here" digest and the AJE WATCH card.
  // Resolved lazily and guarded with typeof so the vm-based unit test (which
  // strips imports) stays happy.
  const startLoginReport =
    initializeLoginReport ||
    (typeof initLoginReport === 'function' ? initLoginReport : null);
  const startAjeAlert =
    typeof initAjeAlert === 'function' ? initAjeAlert : null;
  let resolveDelay;
  const minimumDelay = new Promise((resolve) => {
    resolveDelay = resolve;
  });
  const delayTimer = setTimeout(resolveDelay, 1000);
  const revealFirstRun = () => {
    if (disposed || signal.aborted || firstRun) return;
    firstRun = initializeWelcome?.({ styleManager, dataManager });
    loginReport = startLoginReport?.();
    ajeAlert = startAjeAlert?.();
    clearTimeout(revealTimer);
    loadingScreen.removeEventListener('transitionend', revealFirstRun);
  };
  void Promise.all([styleManager.initialRestorePromise, minimumDelay])
    .catch(() => {
      /* Restoration reports its own outcome through the controls. */
    })
    .then(() => {
      if (disposed || signal.aborted) return;
      loadingScreen.classList.add('hidden');
      loadingScreen.addEventListener('transitionend', revealFirstRun, {
        once: true,
      });
      revealTimer = setTimeout(revealFirstRun, 900);
    });
  const keySetup = Promise.resolve(
    signal.aborted ? null : initializeSettings?.({ signal }),
  );
  // Own the pending initializer too; it must not reveal a dialog after abort.
  void keySetup.catch(() =>
    console.error('Provider settings initialization failed'),
  );
  return async () => {
    disposed = true;
    clearTimeout(delayTimer);
    clearTimeout(revealTimer);
    resolveDelay();
    loadingScreen.removeEventListener('transitionend', revealFirstRun);
    firstRun?.destroy();
    loginReport?.destroy?.();
    ajeAlert?.destroy?.();
    (await keySetup.catch(() => null))?.destroy();
  };
}
