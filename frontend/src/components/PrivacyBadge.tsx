import { ShieldCheck } from 'lucide-react';

export function PrivacyBadge() {
  return (
    <div className="flex items-center justify-center space-x-2 bg-cyber-light/80 border border-cyber-success/30 text-cyber-success px-4 py-2 rounded-lg animate-pulse-fast cyber-glow group">
      <ShieldCheck className="w-5 h-5 group-hover:scale-110 transition-transform" />
      <span className="text-sm font-semibold tracking-wide">
        PRIVACY PROTOCOL ACTIVE: No Decryption Required.
      </span>
    </div>
  );
}
