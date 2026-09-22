import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { cn } from "@/lib/utils";

export function SkillMarkdown({ children }: { children: string }) {
  return (
    <div
      className={cn(
        "prose prose-invert max-w-none",
        "prose-p:my-3 prose-p:leading-relaxed prose-p:text-[13.5px]",
        "prose-headings:font-semibold prose-headings:tracking-tight prose-headings:text-foreground",
        "prose-h1:text-xl prose-h1:mt-6 prose-h1:mb-3 prose-h1:border-b prose-h1:border-border prose-h1:pb-2",
        "prose-h2:text-[15px] prose-h2:mt-6 prose-h2:mb-2 prose-h2:border-b prose-h2:border-border/60 prose-h2:pb-1.5",
        "prose-h3:text-[13px] prose-h3:mt-4 prose-h3:mb-1.5 prose-h3:uppercase prose-h3:tracking-wide prose-h3:text-muted-foreground",
        "prose-a:text-primary prose-a:underline-offset-4 hover:prose-a:underline prose-a:break-words",
        "prose-strong:text-foreground prose-strong:font-semibold",
        "prose-code:text-[12.5px] prose-code:font-mono prose-code:rounded prose-code:bg-muted prose-code:px-1 prose-code:py-0.5 prose-code:font-medium prose-code:before:content-none prose-code:after:content-none",
        "prose-pre:rounded-lg prose-pre:border prose-pre:bg-[#0a0a0a] prose-pre:p-0 prose-pre:overflow-hidden",
        "prose-pre:prose-code:bg-transparent prose-pre:prose-code:p-0 prose-pre:prose-code:rounded-none",
        "prose-ul:my-3 prose-ul:list-disc prose-ul:pl-5 prose-li:my-1 prose-li:text-[13.5px] prose-li:leading-relaxed",
        "prose-ol:my-3 prose-ol:list-decimal prose-ol:pl-5",
        "prose-li:marker:text-muted-foreground",
        "prose-blockquote:border-l-2 prose-blockquote:border-primary/40 prose-blockquote:bg-muted/40 prose-blockquote:rounded-r-md prose-blockquote:px-3 prose-blockquote:py-2 prose-blockquote:text-muted-foreground prose-blockquote:not-italic",
        "prose-table:my-4 prose-table:w-full prose-table:overflow-hidden prose-table:rounded-md prose-table:border prose-table:text-sm",
        "prose-th:bg-muted/60 prose-th:px-3 prose-th:py-2 prose-th:text-left prose-th:font-medium prose-th:text-xs prose-th:uppercase prose-th:tracking-wide",
        "prose-td:px-3 prose-td:py-2 prose-td:border-t prose-td:text-[13px]",
        "prose-hr:my-6 prose-hr:border-border",
        "prose-img:rounded-lg prose-img:border",
      )}
    >
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          a: ({ children, href, ...props }) => (
            <a href={href} target="_blank" rel="noopener noreferrer" {...props}>
              {children}
            </a>
          ),
          pre: ({ children, ...props }) => (
            <pre className="overflow-x-auto p-3 text-xs leading-relaxed scrollbar-thin" {...props}>
              {children}
            </pre>
          ),
          table: ({ children, ...props }) => (
            <div className="overflow-x-auto">
              <table {...props}>{children}</table>
            </div>
          ),
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
}
