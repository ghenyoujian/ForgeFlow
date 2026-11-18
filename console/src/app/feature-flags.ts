/** Opt in per browser; ?workbench=1|0 offers an immediate rollback path. */
export function planningWorkbenchEnabled() {
  const value = new URLSearchParams(window.location.search).get('workbench');
  if (value === '1' || value === '0') localStorage.setItem('forgeflow.planning-workbench', value);
  return (value ?? localStorage.getItem('forgeflow.planning-workbench') ?? (sessionStorage.getItem('forgeflow.personal-account')==='1'?'1':'0')) === '1';
}
