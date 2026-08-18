export function AuditRecordsTable({ records }: { records: Record<string, unknown>[] }) {
  const columns = Array.from(new Set(records.flatMap((rec) => Object.keys(rec)))).slice(0, 6);
  return (
    <div className="overflow-x-auto rounded-md border">
      <table className="w-full border-collapse text-xs">
        <caption className="sr-only">Audit records</caption>
        <thead>
          <tr>
            {columns.map((k) => (
              <th key={k} scope="col" className="bg-muted/40 px-3 py-2.5 text-left font-medium uppercase tracking-wide text-muted-foreground">
                {k}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {records.map((rec, i) => {
            const key = String(rec.id ?? rec.sequence ?? i);
            return (
              <tr key={key} className="border-t">
                {columns.map((k) => (
                  <td key={k} className="max-w-xs truncate px-3 py-2.5 font-mono" title={String(rec[k] ?? "")}>
                    {String(rec[k] ?? "")}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
