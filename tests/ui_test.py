from playwright.sync_api import sync_playwright
import glob
exe = [p for p in glob.glob('/opt/pw-browsers/**/chrome', recursive=True)+glob.glob('/opt/pw-browsers/chromium*') if not p.endswith('.zip')]
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={'width':1500,'height':1300})
    pg.goto('http://localhost:8501'); pg.wait_for_timeout(5000)
    # pick TC08
    pg.locator('[data-testid="stSelectbox"]').filter(has_text='Alert queue').click(); pg.wait_for_timeout(800)
    pg.get_by_role('option', name='TC08').click(); pg.wait_for_timeout(1500)
    pg.get_by_role('button', name='▶ Run agentic triage').click(); pg.wait_for_timeout(5000)
    pg.screenshot(path='/tmp/ui1.png', full_page=True)
    pg.get_by_label('Analyst comment / justification').fill('Ransomware confirmed, isolate'); pg.keyboard.press('Enter'); pg.wait_for_timeout(1500)
    pg.get_by_role('button', name='✅ Approve selected actions').click(); pg.wait_for_timeout(3000)
    pg.screenshot(path='/tmp/ui2.png', full_page=True)
    pg.get_by_role('tab', name='📊 Model Benchmark').click(); pg.wait_for_timeout(1000)
    pg.get_by_role('button', name='▶ Run benchmark').click(); pg.wait_for_timeout(12000)
    pg.screenshot(path='/tmp/ui3.png', full_page=True)
    b.close()
