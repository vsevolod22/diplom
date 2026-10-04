import type { ComponentProps } from 'react';
import * as AccordionPrimitive from '@radix-ui/react-accordion';
import { ChevronDown } from 'lucide-react';

// Adapted from shadcn/ui Accordion (21st.dev): Radix disclosure with a rotating icon.
export function ReportAccordion(props: ComponentProps<typeof AccordionPrimitive.Root>) {
  return <AccordionPrimitive.Root data-slot="accordion" className="scan-report-guide" {...props} />;
}

export function ReportAccordionItem(props: ComponentProps<typeof AccordionPrimitive.Item>) {
  return (
    <AccordionPrimitive.Item data-slot="accordion-item" className="scan-report-guide__item" {...props} />
  );
}

export function ReportAccordionTrigger({
  children,
  ...props
}: ComponentProps<typeof AccordionPrimitive.Trigger>) {
  return (
    <AccordionPrimitive.Header className="scan-report-guide__header">
      <AccordionPrimitive.Trigger
        data-slot="accordion-trigger"
        className="scan-report-guide__trigger"
        {...props}
      >
        {children}
        <ChevronDown size={20} className="scan-report-guide__chevron" aria-hidden="true" />
      </AccordionPrimitive.Trigger>
    </AccordionPrimitive.Header>
  );
}

export function ReportAccordionContent({
  children,
  ...props
}: ComponentProps<typeof AccordionPrimitive.Content>) {
  return (
    <AccordionPrimitive.Content
      data-slot="accordion-content"
      className="scan-report-guide__content"
      {...props}
    >
      <div className="scan-report-guide__content-inner">{children}</div>
    </AccordionPrimitive.Content>
  );
}
