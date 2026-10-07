import csv
from backend.app.main import classify_url
labels=['Legitimate','Suspicious','Phishing']
rows=list(csv.DictReader(open('data/url_test_cases.csv',encoding='utf-8')))
y_true=[r['expected'] for r in rows]
y_pred=[classify_url(r['url'])['classification'] for r in rows]
cm={(a,b):sum(1 for y,p in zip(y_true,y_pred) if y==a and p==b) for a in labels for b in labels}
for label in labels:
    tp=cm[(label,label)]; fp=sum(cm[(x,label)] for x in labels if x!=label); fn=sum(cm[(label,x)] for x in labels if x!=label)
    precision=tp/(tp+fp) if tp+fp else 0; recall=tp/(tp+fn) if tp+fn else 0
    f1=2*precision*recall/(precision+recall) if precision+recall else 0
    print(f'{label}: precision={precision:.3f} recall={recall:.3f} f1={f1:.3f}')
accuracy=sum(a==b for a,b in zip(y_true,y_pred))/len(y_true)
print(f'accuracy={accuracy:.3f}')
print('confusion_matrix rows=true, cols=predicted')
print('              Legitimate  Suspicious  Phishing')
for label in labels:
 print(f'{label:<14}{cm[(label,"Legitimate")]:10d}{cm[(label,"Suspicious")]:12d}{cm[(label,"Phishing")]:10d}')
