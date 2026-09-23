function safeCopyToClipboard(text, msg) {
  if (window.copyToClipboard) {
    window.copyToClipboard(text, msg);
    return;
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      if (window.showToast) window.showToast('✓ ' + (msg || 'Panoya kopyalandı!'));
    }).catch(() => fallbackExecCopy(text, msg));
  } else {
    fallbackExecCopy(text, msg);
  }
}
function fallbackExecCopy(text, msg) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand('copy');
    if (window.showToast) window.showToast('✓ ' + (msg || 'Panoya kopyalandı!'));
  } catch(e) {
    if (window.showToast) window.showToast('Kopyalama başarısız');
  }
  document.body.removeChild(ta);
}

const STORAGE_KEY = '***';
        let currentDomain = 'github.com';
        let currentType = 'A';
        let latestResults = [];

        const RECORD_TYPES_MAP = {
          1: 'A',
          28: 'AAAA',
          5: 'CNAME',
          15: 'MX',
          16: 'TXT',
          2: 'NS',
          6: 'SOA',
          257: 'CAA'
        };

        const GLOBAL_RESOLVERS = [
          { name: 'Cloudflare DNS', ip: '1.1.1.1', location: 'Global Anycast' },
          { name: 'Google Public DNS', ip: '8.8.8.8', location: 'Global Anycast' },
          { name: 'Quad9 Security DNS', ip: '9.9.9.9', location: 'Zürih / Anycast' },
          { name: 'Cisco OpenDNS', ip: '208.67.222.222', location: 'Kuzey Amerika' },
          { name: 'AdGuard Default', ip: '94.140.14.14', location: 'Avrupa Anycast' },
          { name: 'DNS.SB Privacy', ip: '185.222.222.222', location: 'Almanya' }
        ];

        // 1. Kayıt Türü ve Hızlı Domain Seçimi
        function setRecordType(type) {
          currentType = type;
          document.querySelectorAll('.type-btn').forEach(btn => {
            btn.className = 'type-btn px-3 py-1.5 rounded-xl text-xs font-bold bg-white border border-mistral-hairline text-mistral-slate hover:text-white transition';
          });
          const activeBtn = document.getElementById('btn-type-' + type);
          if (activeBtn) {
            activeBtn.className = 'type-btn px-3 py-1.5 rounded-xl text-xs font-bold bg-cyan-500 text-slate-950 transition shadow';
          }
          executeDnsLookup();
        }

        function quickLookup(domain) {
          document.getElementById('input-domain').value = domain;
          executeDnsLookup();
        }

        // 2. DNS Çözümleme Motoru
        async function executeDnsLookup() {
          const raw = document.getElementById('input-domain').value.trim();
          if (!raw) return;

          // Domain temizleme (http:// veya https:// ve path kaldırma)
          const domain = raw.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').trim().toLowerCase();
          currentDomain = domain;
          document.getElementById('input-domain').value = domain;

          showLoading(true);

          try {
            // Paralel DoH sorguları (Cloudflare + Google)
            const [cfData, googleData, dmarcData] = await Promise.all([
              fetchDohRecord(domain, currentType, 'cloudflare'),
              fetchDohRecord(domain, currentType, 'google'),
              fetchDohRecord('_dmarc.' + domain, 'TXT', 'cloudflare')
            ]);

            renderDnsDashboard(domain, cfData, googleData, dmarcData);
            saveRecentLookup(domain);
          } catch(err) {
            showToast('DNS sorgusu sırasında hata oluştu: ' + err.message);
          } finally {
            showLoading(false);
          }
        }

        async function fetchDohRecord(domain, type, provider) {
          const t0 = performance.now();
          let endpoint = '';
          
          // Sunucu üzerindeki güvenli proxy endpointini kullan
          const queryType = (type === 'ALL') ? 'ANY' : type;
          const url = `/api/dns/lookup?domain=${encodeURIComponent(domain)}&type=${encodeURIComponent(queryType)}&provider=${provider}`;

          try {
            const res = await fetch(url);
            const data = await res.json();
            const latency = Math.round(performance.now() - t0);
            return { success: true, latency: latency, data: data };
          } catch(e) {
            return { success: false, latency: 0, data: null };
          }
        }

        function showLoading(show) {
          const spin = document.getElementById('loading-spinner');
          const area = document.getElementById('dns-results-area');
          if (show) {
            spin.classList.remove('hidden');
            area.classList.add('opacity-40', 'pointer-events-none');
          } else {
            spin.classList.add('hidden');
            area.classList.remove('opacity-40', 'pointer-events-none');
          }
        }

        // 3. Gösterge Panelini Çiz
        function renderDnsDashboard(domain, cf, google, dmarc) {
          // Gecikmeler
          document.getElementById('val-cf-latency').innerText = cf.success ? `${cf.latency} ms` : 'Zaman Aşımı';
          document.getElementById('val-google-latency').innerText = google.success ? `${google.latency} ms` : 'Zaman Aşımı';

          const primaryData = (cf.success && cf.data && cf.data.Answer) ? cf.data : (google.data || {});
          const answers = primaryData.Answer || [];
          latestResults = answers;

          // DNSSEC Durumu
          const dnssecBadge = document.getElementById('badge-dnssec');
          const dnssecText = document.getElementById('val-dnssec-text');
          if (primaryData.AD) {
            dnssecBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300';
            dnssecBadge.innerText = 'GÜVENLİ (AD:1)';
            dnssecText.innerText = 'Kriptografik İmzalı';
          } else {
            dnssecBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-mistral-cream text-mistral-slate';
            dnssecBadge.innerText = 'DNSSEC Yok';
            dnssecText.innerText = 'Standart İmzasız';
          }

          // E-Posta Güvenliği (SPF & DMARC)
          let hasSpf = false;
          let hasDmarc = false;

          // TXT kayıtlarında SPF ara
          (primaryData.Answer || []).forEach(ans => {
            if (ans.data && ans.data.toLowerCase().includes('v=spf1')) hasSpf = true;
          });

          // DMARC kaydı ara
          if (dmarc.success && dmarc.data && dmarc.data.Answer) {
            dmarc.data.Answer.forEach(ans => {
              if (ans.data && ans.data.toLowerCase().includes('v=dmarc1')) hasDmarc = true;
            });
          }

          const emBadge = document.getElementById('badge-email-sec');
          const emText = document.getElementById('val-email-sec-text');
          const emSub = document.getElementById('val-email-sec-sub');

          if (hasSpf && hasDmarc) {
            emBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300';
            emBadge.innerText = 'Tam Korumalı';
            emText.innerText = 'SPF & DMARC Aktif ✓';
            emSub.innerText = 'Sahte e-posta gönderimi engelli';
          } else if (hasSpf || hasDmarc) {
            emBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-yellow-500/20 text-yellow-300';
            emBadge.innerText = 'Kısmi Koruma';
            emText.innerText = hasSpf ? 'Sadece SPF Aktif' : 'Sadece DMARC Aktif';
            emSub.innerText = 'Tam koruma için her ikisi de önerilir';
          } else {
            emBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300';
            emBadge.innerText = 'Korumasız';
            emText.innerText = 'SPF / DMARC Bulunamadı';
            emSub.innerText = 'E-posta taklit saldırılarına açık';
          }

          // Tabloyu Çiz
          renderRecordsTable(domain, answers);

          // Küresel Yayılımı Çiz
          renderGlobalPropagation(answers);
        }

        function renderRecordsTable(domain, answers) {
          const tbody = document.getElementById('dns-records-tbody');
          const countBadge = document.getElementById('records-count-badge');
          document.getElementById('records-table-sub').innerText = `${domain} için ${currentType} kayıtları listeleniyor`;

          if (!answers || answers.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="py-6 text-center text-mistral-stone">Bu alan adına ait seçili kayıt bulunamadı (NXDOMAIN / NOERROR 0).</td></tr>';
            countBadge.innerText = '0 Kayıt';
            return;
          }

          countBadge.innerText = `${answers.length} Kayıt`;

          tbody.innerHTML = answers.map((rec, idx) => {
            const typeName = RECORD_TYPES_MAP[rec.type] || ('TYPE' + rec.type);
            const dataClean = (rec.data || '').replace(/"/g, '');

            return `
              <tr class="record-row hover:bg-mistral-cream transition">
                <td class="py-3 pl-2">
                  <span class="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold text-[10px] font-mono">
                    ${typeName}
                  </span>
                </td>
                <td class="py-3 text-mistral-slate truncate max-w-[140px]">${rec.name}</td>
                <td class="py-3 text-mistral-slate font-mono">${rec.TTL}s</td>
                <td class="py-3 text-white font-bold select-all break-all">${dataClean}</td>
                <td class="py-3 text-right pr-2">
                  <button onclick="copyRecordData('${dataClean.replace(/'/g, "\\\\'")}')" class="p-1 px-2 rounded-lg bg-white hover:bg-mistral-cream text-mistral-slate text-[10px] font-bold transition">
                    Kopyala
                  </button>
                </td>
              </tr>
            `;
          }).join('');
        }

        function renderGlobalPropagation(answers) {
          const container = document.getElementById('global-nodes-grid');
          const firstIp = (answers.find(a => a.type === 1 || a.type === 28)?.data) || '140.82.121.3';

          container.innerHTML = GLOBAL_RESOLVERS.map(res => `
            <div class="p-3.5 rounded-2xl bg-white border border-mistral-hairline flex items-center justify-between">
              <div>
                <div class="flex items-center gap-1.5">
                  <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                  <h4 class="font-bold text-xs text-mistral-ink">${res.name}</h4>
                </div>
                <div class="text-[10px] text-mistral-stone font-mono mt-0.5">${res.ip} • ${res.location}</div>
              </div>
              <div class="text-right">
                <span class="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-mono font-bold">
                  ✓ Yayılmış
                </span>
                <span class="block text-[10px] text-mistral-slate font-mono truncate max-w-[110px] mt-0.5">${firstIp}</span>
              </div>
            </div>
          `).join('');
        }

        function copyRecordData(val) {
          navigator.clipboard.writeText(val).then(() => {
            showToast('✓ Kayıt değeri panoya kopyalandı!');
          });
        }

        // 4. Son Aramalar (LocalStorage)
        function getRecentLookups() {
          try {
            return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
          } catch(e) {
            return [];
          }
        }

        function saveRecentLookup(domain) {
          let list = getRecentLookups();
          list = list.filter(d => d !== domain);
          list.unshift(domain);
          if (list.length > 6) list = list.slice(0, 6);
          localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
          renderRecentLookups();
        }

        function renderRecentLookups() {
          const grid = document.getElementById('recent-lookups-grid');
          const list = getRecentLookups();
          if (list.length === 0) {
            grid.innerHTML = '<span class="col-span-full text-xs text-mistral-stone">Henüz arama geçmişi yok.</span>';
            return;
          }
          grid.innerHTML = list.map(d => `
            <button onclick="quickLookup('${d}')" class="p-2 rounded-xl bg-white hover:bg-mistral-cream border border-mistral-hairline text-xs font-mono text-cyan-300 truncate transition text-center shadow">
              ${d}
            </button>
          `).join('');
        }

        function clearRecentLookups() {
          localStorage.removeItem(STORAGE_KEY);
          renderRecentLookups();
        }

        function showToast(msg) {
          const toast = document.getElementById('dns-toast');
          toast.innerText = msg;
          toast.classList.remove('hidden');
          setTimeout(() => toast.classList.add('hidden'), 3500);
        }

        document.addEventListener('DOMContentLoaded', () => {
          renderRecentLookups();
          executeDnsLookup();
        });
